use alloc::{
    collections::{BTreeMap, VecDeque},
    string::{String, ToString},
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::ffi::{c_char, c_int, c_void};
use core::mem::size_of;
use core::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axerrno::{AxError, LinuxError, LinuxResult};
use axio::PollState;
use axnet::{Shutdown as TcpShutdown, TcpSocket, UdpSocket};
use axsync::Mutex;
use axtask::WaitQueue;
use lazy_static::lazy_static;

use super::fd_ops::{FD_CLOEXEC_FLAG, FileLike, add_file_like_with_fd_flags};
use super::pipe::Pipe;
use crate::ctypes;
use crate::utils::char_ptr_to_str;

const AI_PASSIVE: i32 = 0x01;
const SOL_IP: i32 = 0;
const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;
const IP_ADD_MEMBERSHIP: i32 = 35;
const IP_DROP_MEMBERSHIP: i32 = 36;
const MCAST_JOIN_GROUP: i32 = 42;
const MCAST_LEAVE_GROUP: i32 = 45;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_SCTP: i32 = 132;
const IPPROTO_UDPLITE: i32 = 136;
const IPPROTO_SCTP_U32: u32 = 132;
const IPPROTO_UDPLITE_U32: u32 = 136;
const O_PATH: usize = 0o10000000;
const TCP_NODELAY: i32 = 1;
const TCP_MAXSEG: i32 = 2;
const TCP_INFO: i32 = 11;
const DEFAULT_SOCK_BUF: i32 = 256 * 1024;
const DEFAULT_TCP_MAXSEG: i32 = 1460;
const SHUT_RD: i32 = 0;
const SHUT_WR: i32 = 1;
const SHUT_RDWR: i32 = 2;
const SHUT_RD_FLAG: usize = 1;
const SHUT_WR_FLAG: usize = 2;
const UNIX_PATH_MAX: usize = 108;
const UNIX_FAMILY_LEN: usize = size_of::<u16>();

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxTcpInfo {
    tcpi_state: u8,
    tcpi_ca_state: u8,
    tcpi_retransmits: u8,
    tcpi_probes: u8,
    tcpi_backoff: u8,
    tcpi_options: u8,
    tcpi_snd_rcv_wscale: u8,
    tcpi_delivery_rate_app_limited: u8,
    tcpi_rto: u32,
    tcpi_ato: u32,
    tcpi_snd_mss: u32,
    tcpi_rcv_mss: u32,
    tcpi_unacked: u32,
    tcpi_sacked: u32,
    tcpi_lost: u32,
    tcpi_retrans: u32,
    tcpi_fackets: u32,
    tcpi_last_data_sent: u32,
    tcpi_last_ack_sent: u32,
    tcpi_last_data_recv: u32,
    tcpi_last_ack_recv: u32,
    tcpi_pmtu: u32,
    tcpi_rcv_ssthresh: u32,
    tcpi_rtt: u32,
    tcpi_rttvar: u32,
    tcpi_snd_ssthresh: u32,
    tcpi_snd_cwnd: u32,
    tcpi_advmss: u32,
    tcpi_reordering: u32,
    tcpi_rcv_rtt: u32,
    tcpi_rcv_space: u32,
    tcpi_total_retrans: u32,
    tcpi_pacing_rate: u64,
    tcpi_max_pacing_rate: u64,
    tcpi_bytes_acked: u64,
    tcpi_bytes_received: u64,
    tcpi_segs_out: u32,
    tcpi_segs_in: u32,
    tcpi_notsent_bytes: u32,
    tcpi_min_rtt: u32,
    tcpi_data_segs_in: u32,
    tcpi_data_segs_out: u32,
    tcpi_delivery_rate: u64,
    tcpi_busy_time: u64,
    tcpi_rwnd_limited: u64,
    tcpi_sndbuf_limited: u64,
    tcpi_delivered: u32,
    tcpi_delivered_ce: u32,
    tcpi_bytes_sent: u64,
    tcpi_bytes_retrans: u64,
    tcpi_dsack_dups: u32,
    tcpi_reord_seen: u32,
    tcpi_rcv_ooopack: u32,
    tcpi_snd_wnd: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; UNIX_PATH_MAX],
}

#[derive(Clone, Debug)]
enum SockAddrValue {
    Inet(SocketAddr),
    Unix(UnixAddr),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum UnixAddr {
    Unnamed,
    Path(String),
    Abstract(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnixSocketType {
    Stream,
    SeqPacket,
    Dgram,
}

#[derive(Clone)]
struct UnixDatagram {
    data: Vec<u8>,
    from: Option<UnixAddr>,
}

enum UnixSocketState {
    Idle,
    Listener { pending: VecDeque<Arc<UnixSocket>> },
    Connected { endpoint: SocketPairEndpoint },
    Dgram { recvq: VecDeque<UnixDatagram> },
}

struct UnixSocketInner {
    local_addr: Option<UnixAddr>,
    peer_addr: Option<UnixAddr>,
    state: UnixSocketState,
}

struct UnixSocket {
    kind: UnixSocketType,
    inner: Mutex<UnixSocketInner>,
    accept_wait: WaitQueue,
    recv_wait: WaitQueue,
    nonblocking: AtomicBool,
}

lazy_static! {
    static ref UNIX_BOUND: Mutex<BTreeMap<UnixAddr, Weak<UnixSocket>>> =
        Mutex::new(BTreeMap::new());
}

fn unix_bound_map() -> &'static Mutex<BTreeMap<UnixAddr, Weak<UnixSocket>>> {
    &UNIX_BOUND
}

fn normalize_unix_path(path: &str) -> LinuxResult<String> {
    let mut full = if path.starts_with('/') {
        path.to_string()
    } else {
        let mut cwd = axfs::api::current_dir()?;
        if !cwd.ends_with('/') {
            cwd.push('/');
        }
        cwd.push_str(path);
        cwd
    };

    let mut parts: Vec<String> = Vec::new();
    for part in full.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_string()),
        }
    }

    full.clear();
    full.push('/');
    full.push_str(&parts.join("/"));
    if full.len() > 1 && full.ends_with('/') {
        full.pop();
    }
    Ok(full)
}

fn unix_parent_path(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
}

fn validate_unix_parent(path: &str) -> LinuxResult<()> {
    let parent = unix_parent_path(path);
    let mut prefix = String::from("/");
    for comp in parent
        .trim_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
    {
        if prefix.len() > 1 {
            prefix.push('/');
        }
        prefix.push_str(comp);
        let attr = axfs::api::metadata_raw(prefix.as_str())?;
        if !attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }
    }
    Ok(())
}

fn cleanup_dead_unix_entry(addr: &UnixAddr) {
    let mut map = unix_bound_map().lock();
    if map.get(addr).is_some_and(|entry| entry.upgrade().is_none()) {
        map.remove(addr);
    }
}

fn lookup_unix_bound(addr: &UnixAddr) -> Option<Arc<UnixSocket>> {
    let socket = {
        let map = unix_bound_map().lock();
        map.get(addr).and_then(|entry| entry.upgrade())
    };
    if socket.is_none() {
        cleanup_dead_unix_entry(addr);
    }
    socket
}

fn bind_unix_addr(addr: &UnixAddr, socket: &Arc<UnixSocket>) -> LinuxResult<()> {
    let mut map = unix_bound_map().lock();
    if let Some(existing) = map.get(addr).and_then(|entry| entry.upgrade()) {
        if !Arc::ptr_eq(&existing, socket) {
            return Err(LinuxError::EADDRINUSE);
        }
    }
    map.insert(addr.clone(), Arc::downgrade(socket));
    Ok(())
}

fn normalize_local_inet_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v4.port()))
        }
        _ => addr,
    }
}

impl UnixSocket {
    fn new(kind: UnixSocketType) -> Arc<Self> {
        Arc::new(Self {
            kind,
            inner: Mutex::new(UnixSocketInner {
                local_addr: None,
                peer_addr: None,
                state: match kind {
                    UnixSocketType::Dgram => UnixSocketState::Dgram {
                        recvq: VecDeque::new(),
                    },
                    _ => UnixSocketState::Idle,
                },
            }),
            accept_wait: WaitQueue::new(),
            recv_wait: WaitQueue::new(),
            nonblocking: AtomicBool::new(false),
        })
    }

    fn new_connected(
        kind: UnixSocketType,
        endpoint: SocketPairEndpoint,
        local_addr: Option<UnixAddr>,
        peer_addr: Option<UnixAddr>,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            inner: Mutex::new(UnixSocketInner {
                local_addr,
                peer_addr,
                state: UnixSocketState::Connected { endpoint },
            }),
            accept_wait: WaitQueue::new(),
            recv_wait: WaitQueue::new(),
            nonblocking: AtomicBool::new(false),
        })
    }

    fn sock_type(&self) -> c_int {
        match self.kind {
            UnixSocketType::Stream => ctypes::SOCK_STREAM as c_int,
            UnixSocketType::SeqPacket => ctypes::SOCK_SEQPACKET as c_int,
            UnixSocketType::Dgram => ctypes::SOCK_DGRAM as c_int,
        }
    }

    fn set_nonblocking(&self, nonblock: bool) -> LinuxResult {
        self.nonblocking.store(nonblock, Ordering::Release);
        if let UnixSocketState::Connected { endpoint } = &self.inner.lock().state {
            endpoint.set_nonblocking(nonblock)?;
        }
        Ok(())
    }

    fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    fn local_addr(&self) -> LinuxResult<SockAddrValue> {
        Ok(SockAddrValue::Unix(
            self.inner
                .lock()
                .local_addr
                .clone()
                .unwrap_or(UnixAddr::Unnamed),
        ))
    }

    fn peer_addr(&self) -> LinuxResult<SockAddrValue> {
        self.inner
            .lock()
            .peer_addr
            .clone()
            .map(SockAddrValue::Unix)
            .ok_or(LinuxError::ENOTCONN)
    }

    fn bind(self: &Arc<Self>, addr: UnixAddr) -> LinuxResult {
        if addr == UnixAddr::Unnamed {
            return Err(LinuxError::EINVAL);
        }
        if self.inner.lock().local_addr.is_some() {
            return Err(LinuxError::EINVAL);
        }

        if let UnixAddr::Path(path) = &addr {
            validate_unix_parent(path)?;
            if axfs::api::absolute_path_exists(path) {
                return Err(LinuxError::EADDRINUSE);
            }
        }

        if let UnixAddr::Path(path) = &addr {
            axfs::api::create_socket(path)?;
        }
        bind_unix_addr(&addr, self)?;

        let mut inner = self.inner.lock();
        inner.local_addr = Some(addr);
        Ok(())
    }

    fn connect(self: &Arc<Self>, addr: UnixAddr) -> LinuxResult {
        match self.kind {
            UnixSocketType::Stream | UnixSocketType::SeqPacket => self.connect_stream(addr),
            UnixSocketType::Dgram => self.connect_dgram(addr),
        }
    }

    fn connect_stream(self: &Arc<Self>, addr: UnixAddr) -> LinuxResult {
        let listener = lookup_unix_bound(&addr).ok_or_else(|| match addr {
            UnixAddr::Path(ref path) if !axfs::api::absolute_path_exists(path) => {
                LinuxError::ENOENT
            }
            _ => LinuxError::ECONNREFUSED,
        })?;
        if listener.kind != self.kind {
            return Err(LinuxError::EPROTOTYPE);
        }

        let server_local = {
            let listener_inner = listener.inner.lock();
            match &listener_inner.state {
                UnixSocketState::Listener { .. } => listener_inner.local_addr.clone(),
                _ => return Err(LinuxError::ECONNREFUSED),
            }
        };

        let mut inner = self.inner.lock();
        if inner.peer_addr.is_some() {
            return Err(LinuxError::EISCONN);
        }
        match inner.state {
            UnixSocketState::Idle => {}
            _ => return Err(LinuxError::EINVAL),
        }
        let (client_end, server_end) = SocketPairEndpoint::new_pair();
        let client_local = inner.local_addr.clone().or(Some(UnixAddr::Unnamed));
        inner.peer_addr = Some(addr.clone());
        inner.local_addr = client_local.clone();
        inner.state = UnixSocketState::Connected {
            endpoint: client_end,
        };
        drop(inner);

        let accepted = UnixSocket::new_connected(self.kind, server_end, server_local, client_local);
        let mut listener_inner = listener.inner.lock();
        match &mut listener_inner.state {
            UnixSocketState::Listener { pending } => {
                pending.push_back(accepted);
                listener.accept_wait.notify_one(true);
                Ok(())
            }
            _ => Err(LinuxError::ECONNREFUSED),
        }
    }

    fn connect_dgram(self: &Arc<Self>, addr: UnixAddr) -> LinuxResult {
        let peer = lookup_unix_bound(&addr).ok_or_else(|| match addr {
            UnixAddr::Path(ref path) if !axfs::api::absolute_path_exists(path) => {
                LinuxError::ENOENT
            }
            _ => LinuxError::ECONNREFUSED,
        })?;
        if peer.kind != UnixSocketType::Dgram {
            return Err(LinuxError::EPROTOTYPE);
        }
        let mut inner = self.inner.lock();
        match inner.state {
            UnixSocketState::Dgram { .. } => {
                inner.peer_addr = Some(addr);
                Ok(())
            }
            _ => Err(LinuxError::EINVAL),
        }
    }

    fn listen(&self) -> LinuxResult {
        if self.kind == UnixSocketType::Dgram {
            return Err(LinuxError::EOPNOTSUPP);
        }
        let mut inner = self.inner.lock();
        if inner.local_addr.is_none() {
            return Err(LinuxError::EINVAL);
        }
        match inner.state {
            UnixSocketState::Idle => {
                inner.state = UnixSocketState::Listener {
                    pending: VecDeque::new(),
                };
                Ok(())
            }
            UnixSocketState::Listener { .. } => Ok(()),
            _ => Err(LinuxError::EINVAL),
        }
    }

    fn accept(&self) -> LinuxResult<Arc<UnixSocket>> {
        loop {
            let mut inner = self.inner.lock();
            match &mut inner.state {
                UnixSocketState::Listener { pending } => {
                    if let Some(socket) = pending.pop_front() {
                        return Ok(socket);
                    }
                }
                _ => return Err(LinuxError::EINVAL),
            }
            if self.is_nonblocking() {
                return Err(LinuxError::EAGAIN);
            }
            drop(inner);
            self.accept_wait
                .wait_until(|| match &self.inner.lock().state {
                    UnixSocketState::Listener { pending } => !pending.is_empty(),
                    _ => true,
                });
        }
    }

    fn send(&self, buf: &[u8]) -> LinuxResult<usize> {
        match self.kind {
            UnixSocketType::Stream | UnixSocketType::SeqPacket => match &self.inner.lock().state {
                UnixSocketState::Connected { endpoint } => endpoint.write(buf),
                _ => Err(LinuxError::ENOTCONN),
            },
            UnixSocketType::Dgram => {
                let peer = self
                    .inner
                    .lock()
                    .peer_addr
                    .clone()
                    .ok_or(LinuxError::ENOTCONN)?;
                self.sendto(buf, peer)
            }
        }
    }

    fn sendto(&self, buf: &[u8], addr: UnixAddr) -> LinuxResult<usize> {
        if self.kind != UnixSocketType::Dgram {
            return Err(LinuxError::EISCONN);
        }
        let peer = lookup_unix_bound(&addr).ok_or_else(|| match addr {
            UnixAddr::Path(ref path) if !axfs::api::absolute_path_exists(path) => {
                LinuxError::ENOENT
            }
            _ => LinuxError::ECONNREFUSED,
        })?;
        if peer.kind != UnixSocketType::Dgram {
            return Err(LinuxError::EPROTOTYPE);
        }

        let from = self.inner.lock().local_addr.clone();
        let mut peer_inner = peer.inner.lock();
        match &mut peer_inner.state {
            UnixSocketState::Dgram { recvq } => {
                recvq.push_back(UnixDatagram {
                    data: buf.to_vec(),
                    from,
                });
                drop(peer_inner);
                peer.recv_wait.notify_one(true);
                Ok(buf.len())
            }
            _ => Err(LinuxError::EINVAL),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        self.recvfrom(buf).map(|res| res.0)
    }

    fn recvfrom(&self, buf: &mut [u8]) -> LinuxResult<(usize, Option<SockAddrValue>)> {
        match self.kind {
            UnixSocketType::Stream | UnixSocketType::SeqPacket => match &self.inner.lock().state {
                UnixSocketState::Connected { endpoint } => {
                    endpoint.read(buf).map(|size| (size, None))
                }
                _ => Err(LinuxError::ENOTCONN),
            },
            UnixSocketType::Dgram => loop {
                let mut inner = self.inner.lock();
                match &mut inner.state {
                    UnixSocketState::Dgram { recvq } => {
                        if let Some(msg) = recvq.pop_front() {
                            let size = msg.data.len().min(buf.len());
                            buf[..size].copy_from_slice(&msg.data[..size]);
                            return Ok((size, msg.from.map(SockAddrValue::Unix)));
                        }
                    }
                    _ => return Err(LinuxError::EINVAL),
                }
                if self.is_nonblocking() {
                    return Err(LinuxError::EAGAIN);
                }
                drop(inner);
                self.recv_wait
                    .wait_until(|| match &self.inner.lock().state {
                        UnixSocketState::Dgram { recvq } => !recvq.is_empty(),
                        _ => true,
                    });
            },
        }
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let inner = self.inner.lock();
        Ok(match &inner.state {
            UnixSocketState::Listener { pending } => PollState {
                readable: !pending.is_empty(),
                writable: false,
            },
            UnixSocketState::Connected { endpoint } => endpoint.poll()?,
            UnixSocketState::Dgram { recvq } => PollState {
                readable: !recvq.is_empty(),
                writable: true,
            },
            UnixSocketState::Idle => PollState {
                readable: false,
                writable: true,
            },
        })
    }

    fn shutdown(&self, how: c_int) -> LinuxResult {
        if how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR {
            return Err(LinuxError::EINVAL);
        }
        Ok(())
    }
}

pub struct SocketPairEndpoint {
    read_end: Pipe,
    write_end: Pipe,
}

impl SocketPairEndpoint {
    fn new_pair() -> (Self, Self) {
        let (left_read, right_write) = Pipe::new();
        let (right_read, left_write) = Pipe::new();
        (
            Self {
                read_end: left_read,
                write_end: left_write,
            },
            Self {
                read_end: right_read,
                write_end: right_write,
            },
        )
    }
}

impl FileLike for SocketPairEndpoint {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        self.read_end.read(buf)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        self.write_end.write(buf)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o140000 | 0o777u32,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 4096,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let read_state = self.read_end.poll()?;
        let write_state = self.write_end.poll()?;
        Ok(PollState {
            readable: read_state.readable,
            writable: write_state.writable,
        })
    }

    fn set_nonblocking(&self, nonblock: bool) -> LinuxResult {
        self.read_end.set_nonblocking(nonblock)?;
        self.write_end.set_nonblocking(nonblock)?;
        Ok(())
    }

    fn status_flags(&self) -> usize {
        self.read_end.status_flags() | self.write_end.status_flags()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IpMembership {
    level: c_int,
    optname: c_int,
    payload: Vec<u8>,
}

pub enum SocketInner {
    Udp(Mutex<UdpSocket>),
    Tcp(TcpSocket),
    Unix(Arc<UnixSocket>),
}

pub struct Socket {
    inner: SocketInner,
    ip_memberships: Mutex<Vec<IpMembership>>,
    shutdown_state: AtomicUsize,
}

impl Socket {
    fn new(inner: SocketInner) -> Self {
        Self {
            inner,
            ip_memberships: Mutex::new(Vec::new()),
            shutdown_state: AtomicUsize::new(0),
        }
    }

    fn add_to_fd_table(self) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like(Arc::new(self))
    }

    fn add_to_fd_table_with_flags(self, fd_flags: usize) -> LinuxResult<c_int> {
        add_file_like_with_fd_flags(Arc::new(self), fd_flags)
    }

    fn sock_type(&self) -> c_int {
        match &self.inner {
            SocketInner::Udp(_) => ctypes::SOCK_DGRAM as c_int,
            SocketInner::Tcp(_) => ctypes::SOCK_STREAM as c_int,
            SocketInner::Unix(socket) => socket.sock_type(),
        }
    }

    fn getsockopt_value(&self, level: c_int, optname: c_int) -> c_int {
        match (level, optname) {
            (SOL_SOCKET, SO_TYPE) => self.sock_type(),
            (SOL_SOCKET, SO_ERROR) => 0,
            (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => DEFAULT_SOCK_BUF,
            (IPPROTO_TCP, TCP_NODELAY) => 1,
            (IPPROTO_TCP, TCP_MAXSEG) => DEFAULT_TCP_MAXSEG,
            _ => 0,
        }
    }

    fn tcp_info(&self) -> LinuxResult<LinuxTcpInfo> {
        match &self.inner {
            SocketInner::Tcp(_) => Ok(LinuxTcpInfo {
                tcpi_state: 1,
                tcpi_snd_mss: DEFAULT_TCP_MAXSEG as u32,
                tcpi_rcv_mss: DEFAULT_TCP_MAXSEG as u32,
                tcpi_pmtu: 1500,
                tcpi_rcv_ssthresh: DEFAULT_SOCK_BUF as u32,
                tcpi_rtt: 1_000,
                tcpi_rttvar: 100,
                tcpi_snd_ssthresh: DEFAULT_SOCK_BUF as u32,
                tcpi_snd_cwnd: 10,
                tcpi_advmss: DEFAULT_TCP_MAXSEG as u32,
                tcpi_reordering: 3,
                tcpi_rcv_rtt: 1_000,
                tcpi_rcv_space: DEFAULT_SOCK_BUF as u32,
                tcpi_snd_wnd: DEFAULT_SOCK_BUF as u32,
                ..Default::default()
            }),
            _ => Err(LinuxError::ENOPROTOOPT),
        }
    }

    fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        if f.status_flags() & O_PATH != 0 {
            return Err(LinuxError::EBADF);
        }
        f.into_any()
            .downcast::<Self>()
            .map_err(|_| LinuxError::ENOTSOCK)
    }

    fn send(&self, buf: &[u8]) -> LinuxResult<usize> {
        match &self.inner {
            SocketInner::Udp(udpsocket) => Ok(udpsocket.lock().send(buf)?),
            SocketInner::Tcp(tcpsocket) => Ok(tcpsocket.send(buf)?),
            SocketInner::Unix(socket) => socket.send(buf),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        match &self.inner {
            SocketInner::Udp(udpsocket) => {
                let mut socket = udpsocket.lock();
                match socket.recv(buf) {
                    Ok(size) => Ok(size),
                    Err(AxError::NotConnected) => Ok(socket.recv_from(buf)?.0),
                    Err(err) => Err(err.into()),
                }
            }
            SocketInner::Tcp(tcpsocket) => Ok(tcpsocket.recv(buf)?),
            SocketInner::Unix(socket) => socket.recv(buf),
        }
    }

    pub fn poll(&self) -> LinuxResult<PollState> {
        match &self.inner {
            SocketInner::Udp(udpsocket) => Ok(udpsocket.lock().poll()?),
            SocketInner::Tcp(tcpsocket) => Ok(tcpsocket.poll()?),
            SocketInner::Unix(socket) => socket.poll(),
        }
    }

    pub fn epoll_extra_events(&self, requested: u32) -> u32 {
        let shutdown_state = self.shutdown_state.load(Ordering::Acquire);
        let mut events = 0u32;
        if requested & ctypes::EPOLLRDHUP != 0 && shutdown_state & SHUT_RD_FLAG != 0 {
            events |= ctypes::EPOLLRDHUP;
        }
        if requested & ctypes::EPOLLHUP != 0 && shutdown_state == (SHUT_RD_FLAG | SHUT_WR_FLAG) {
            events |= ctypes::EPOLLHUP;
        }
        events
    }

    fn local_addr(&self) -> LinuxResult<SockAddrValue> {
        match &self.inner {
            SocketInner::Udp(udpsocket) => Ok(SockAddrValue::Inet(normalize_local_inet_addr(
                udpsocket.lock().local_addr()?,
            ))),
            SocketInner::Tcp(tcpsocket) => Ok(SockAddrValue::Inet(normalize_local_inet_addr(
                tcpsocket.local_addr()?,
            ))),
            SocketInner::Unix(socket) => socket.local_addr(),
        }
    }

    fn peer_addr(&self) -> LinuxResult<SockAddrValue> {
        match &self.inner {
            SocketInner::Udp(udpsocket) => Ok(SockAddrValue::Inet(udpsocket.lock().peer_addr()?)),
            SocketInner::Tcp(tcpsocket) => Ok(SockAddrValue::Inet(tcpsocket.peer_addr()?)),
            SocketInner::Unix(socket) => socket.peer_addr(),
        }
    }

    fn bind(&self, addr: SockAddrValue) -> LinuxResult {
        match (&self.inner, addr) {
            (SocketInner::Udp(udpsocket), SockAddrValue::Inet(addr)) => {
                Ok(udpsocket.lock().bind(addr)?)
            }
            (SocketInner::Tcp(tcpsocket), SockAddrValue::Inet(addr)) => Ok(tcpsocket.bind(addr)?),
            (SocketInner::Unix(socket), SockAddrValue::Unix(addr)) => socket.bind(addr),
            (SocketInner::Udp(_) | SocketInner::Tcp(_), SockAddrValue::Unix(_))
            | (SocketInner::Unix(_), SockAddrValue::Inet(_)) => Err(LinuxError::EAFNOSUPPORT),
        }
    }

    fn connect(&self, addr: SockAddrValue) -> LinuxResult {
        match (&self.inner, addr) {
            (SocketInner::Udp(udpsocket), SockAddrValue::Inet(addr)) => {
                Ok(udpsocket.lock().connect(addr)?)
            }
            (SocketInner::Tcp(tcpsocket), SockAddrValue::Inet(addr)) => {
                match tcpsocket.connect(addr) {
                    Ok(()) => Ok(()),
                    Err(AxError::AlreadyExists) => Err(LinuxError::EISCONN),
                    Err(err) => Err(err.into()),
                }
            }
            (SocketInner::Unix(socket), SockAddrValue::Unix(addr)) => socket.connect(addr),
            (SocketInner::Udp(_) | SocketInner::Tcp(_), SockAddrValue::Unix(_))
            | (SocketInner::Unix(_), SockAddrValue::Inet(_)) => Err(LinuxError::EAFNOSUPPORT),
        }
    }

    fn sendto(&self, buf: &[u8], addr: SockAddrValue) -> LinuxResult<usize> {
        match (&self.inner, addr) {
            (SocketInner::Udp(udpsocket), SockAddrValue::Inet(addr)) => {
                Ok(udpsocket.lock().send_to(buf, addr)?)
            }
            (SocketInner::Tcp(_), SockAddrValue::Inet(_)) => Err(LinuxError::EISCONN),
            (SocketInner::Unix(socket), SockAddrValue::Unix(addr)) => socket.sendto(buf, addr),
            (SocketInner::Udp(_) | SocketInner::Tcp(_), SockAddrValue::Unix(_))
            | (SocketInner::Unix(_), SockAddrValue::Inet(_)) => Err(LinuxError::EAFNOSUPPORT),
        }
    }

    fn recvfrom(&self, buf: &mut [u8]) -> LinuxResult<(usize, Option<SockAddrValue>)> {
        match &self.inner {
            SocketInner::Udp(udpsocket) => Ok(udpsocket
                .lock()
                .recv_from(buf)
                .map(|res| (res.0, Some(SockAddrValue::Inet(res.1))))?),
            SocketInner::Tcp(tcpsocket) => Ok(tcpsocket.recv(buf).map(|res| (res, None))?),
            SocketInner::Unix(socket) => socket.recvfrom(buf),
        }
    }

    fn listen(&self) -> LinuxResult {
        match &self.inner {
            SocketInner::Udp(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Tcp(tcpsocket) => Ok(tcpsocket.listen()?),
            SocketInner::Unix(socket) => socket.listen(),
        }
    }

    fn accept(&self) -> LinuxResult<Socket> {
        match &self.inner {
            SocketInner::Udp(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Tcp(tcpsocket) => Ok(Self::new(SocketInner::Tcp(tcpsocket.accept()?))),
            SocketInner::Unix(socket) => Ok(Self::new(SocketInner::Unix(socket.accept()?))),
        }
    }

    fn shutdown(&self, how: c_int) -> LinuxResult {
        match &self.inner {
            SocketInner::Udp(udpsocket) => {
                let udpsocket = udpsocket.lock();
                udpsocket.peer_addr()?;
                udpsocket.shutdown()?;
                self.shutdown_state
                    .store(SHUT_RD_FLAG | SHUT_WR_FLAG, Ordering::Release);
                Ok(())
            }
            SocketInner::Tcp(tcpsocket) => {
                tcpsocket.peer_addr()?;
                let (how, mask) = match how {
                    SHUT_RD => (TcpShutdown::Read, SHUT_RD_FLAG),
                    SHUT_WR => (TcpShutdown::Write, SHUT_WR_FLAG),
                    SHUT_RDWR => (TcpShutdown::ReadWrite, SHUT_RD_FLAG | SHUT_WR_FLAG),
                    _ => return Err(LinuxError::EINVAL),
                };
                tcpsocket.shutdown(how)?;
                self.shutdown_state.fetch_or(mask, Ordering::AcqRel);
                Ok(())
            }
            SocketInner::Unix(socket) => {
                socket.shutdown(how)?;
                let mask = match how {
                    SHUT_RD => SHUT_RD_FLAG,
                    SHUT_WR => SHUT_WR_FLAG,
                    SHUT_RDWR => SHUT_RD_FLAG | SHUT_WR_FLAG,
                    _ => return Err(LinuxError::EINVAL),
                };
                self.shutdown_state.fetch_or(mask, Ordering::AcqRel);
                Ok(())
            }
        }
    }

    fn set_recv_timeout(&self, timeout: Option<core::time::Duration>) {
        match &self.inner {
            SocketInner::Udp(udpsocket) => udpsocket.lock().set_recv_timeout(timeout),
            SocketInner::Tcp(tcpsocket) => tcpsocket.set_recv_timeout(timeout),
            SocketInner::Unix(_) => {}
        }
    }

    fn set_send_timeout(&self, timeout: Option<core::time::Duration>) {
        match &self.inner {
            SocketInner::Udp(udpsocket) => udpsocket.lock().set_send_timeout(timeout),
            SocketInner::Tcp(tcpsocket) => tcpsocket.set_send_timeout(timeout),
            SocketInner::Unix(_) => {}
        }
    }

    fn supports_ip_sockopts(&self) -> bool {
        matches!(&self.inner, SocketInner::Udp(_) | SocketInner::Tcp(_))
    }

    fn remember_ip_membership(
        &self,
        level: c_int,
        optname: c_int,
        optval: *const c_void,
        optlen: ctypes::socklen_t,
    ) -> LinuxResult<()> {
        if !self.supports_ip_sockopts() {
            return Err(LinuxError::ENOPROTOOPT);
        }
        if optval.is_null() || optlen <= 0 {
            return Err(LinuxError::EINVAL);
        }
        let payload = unsafe { core::slice::from_raw_parts(optval.cast::<u8>(), optlen as usize) };
        let membership = IpMembership {
            level,
            optname,
            payload: payload.to_vec(),
        };
        let mut memberships = self.ip_memberships.lock();
        if !memberships.iter().any(|existing| *existing == membership) {
            memberships.push(membership);
        }
        Ok(())
    }

    fn forget_ip_membership(
        &self,
        level: c_int,
        join_optname: c_int,
        optval: *const c_void,
        optlen: ctypes::socklen_t,
    ) -> LinuxResult<()> {
        if !self.supports_ip_sockopts() {
            return Err(LinuxError::ENOPROTOOPT);
        }
        if optval.is_null() || optlen <= 0 {
            return Err(LinuxError::EINVAL);
        }
        let payload = unsafe { core::slice::from_raw_parts(optval.cast::<u8>(), optlen as usize) };
        let mut memberships = self.ip_memberships.lock();
        let Some(index) = memberships.iter().position(|membership| {
            membership.level == level
                && membership.optname == join_optname
                && membership.payload.as_slice() == payload
        }) else {
            return Err(LinuxError::EADDRNOTAVAIL);
        };
        memberships.swap_remove(index);
        Ok(())
    }
}

impl FileLike for Socket {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        self.recv(buf)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        self.send(buf)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let st_mode = 0o140000 | 0o777u32;
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 4096,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        self.poll()
    }

    fn set_nonblocking(&self, nonblock: bool) -> LinuxResult {
        match &self.inner {
            SocketInner::Udp(udpsocket) => udpsocket.lock().set_nonblocking(nonblock),
            SocketInner::Tcp(tcpsocket) => tcpsocket.set_nonblocking(nonblock),
            SocketInner::Unix(socket) => socket.set_nonblocking(nonblock)?,
        }
        Ok(())
    }

    fn status_flags(&self) -> usize {
        let mut flags = ctypes::O_RDWR as usize;
        let nonblocking = match &self.inner {
            SocketInner::Udp(udpsocket) => udpsocket.lock().is_nonblocking(),
            SocketInner::Tcp(tcpsocket) => tcpsocket.is_nonblocking(),
            SocketInner::Unix(socket) => socket.is_nonblocking(),
        };
        if nonblocking {
            flags |= ctypes::O_NONBLOCK as usize;
        }
        flags
    }
}

impl From<SocketAddrV4> for ctypes::sockaddr_in {
    fn from(addr: SocketAddrV4) -> ctypes::sockaddr_in {
        ctypes::sockaddr_in {
            sin_family: ctypes::AF_INET as u16,
            sin_port: addr.port().to_be(),
            sin_addr: ctypes::in_addr {
                // `s_addr` is stored as BE on all machines and the array is in BE order.
                // So the native endian conversion method is used so that it's never swapped.
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        }
    }
}

impl From<ctypes::sockaddr_in> for SocketAddrV4 {
    fn from(addr: ctypes::sockaddr_in) -> SocketAddrV4 {
        SocketAddrV4::new(
            Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(addr.sin_port),
        )
    }
}

fn into_sockaddr(addr: SockAddrValue) -> ([u8; size_of::<SockAddrUn>()], ctypes::socklen_t) {
    let mut out = [0u8; size_of::<SockAddrUn>()];
    match addr {
        SockAddrValue::Inet(addr) => {
            debug!("    Sockaddr(inet): {}", addr);
            match addr {
                SocketAddr::V4(addr) => {
                    let raw = ctypes::sockaddr_in::from(addr);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            (&raw as *const ctypes::sockaddr_in).cast::<u8>(),
                            out.as_mut_ptr(),
                            size_of::<ctypes::sockaddr_in>(),
                        );
                    }
                    (out, size_of::<ctypes::sockaddr_in>() as _)
                }
                SocketAddr::V6(_) => panic!("IPv6 is not supported"),
            }
        }
        SockAddrValue::Unix(addr) => {
            let mut raw = SockAddrUn {
                sun_family: ctypes::AF_UNIX as u16,
                sun_path: [0; UNIX_PATH_MAX],
            };
            let actual_len = match addr {
                UnixAddr::Unnamed => UNIX_FAMILY_LEN,
                UnixAddr::Path(path) => {
                    let bytes = path.as_bytes();
                    let copy_len = bytes.len().min(UNIX_PATH_MAX.saturating_sub(1));
                    raw.sun_path[..copy_len].copy_from_slice(&bytes[..copy_len]);
                    UNIX_FAMILY_LEN + copy_len + 1
                }
                UnixAddr::Abstract(name) => {
                    let copy_len = name.len().min(UNIX_PATH_MAX.saturating_sub(1));
                    raw.sun_path[0] = 0;
                    raw.sun_path[1..1 + copy_len].copy_from_slice(&name[..copy_len]);
                    UNIX_FAMILY_LEN + 1 + copy_len
                }
            };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (&raw as *const SockAddrUn).cast::<u8>(),
                    out.as_mut_ptr(),
                    size_of::<SockAddrUn>(),
                );
            }
            (out, actual_len as _)
        }
    }
}

unsafe fn copy_sockaddr_to_user(
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
    value: SockAddrValue,
) -> LinuxResult<()> {
    if addr.is_null() || addrlen.is_null() {
        return Err(LinuxError::EFAULT);
    }
    let (sockaddr, actual_len) = into_sockaddr(value);
    let raw_user_len = unsafe { *addrlen };
    if (raw_user_len as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }
    let user_len = raw_user_len as usize;
    let copy_len = user_len.min(actual_len as usize);
    if copy_len > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(sockaddr.as_ptr(), addr.cast::<u8>(), copy_len);
        }
    }
    unsafe {
        *addrlen = actual_len;
    }
    Ok(())
}

fn from_sockaddr(
    addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> LinuxResult<SockAddrValue> {
    if addr.is_null() {
        return Err(LinuxError::EFAULT);
    }
    if addrlen < UNIX_FAMILY_LEN as _ {
        return Err(LinuxError::EINVAL);
    }

    let family = unsafe { (*(addr.cast::<u16>())) as i32 };
    match family as u32 {
        ctypes::AF_INET => {
            if addrlen < size_of::<ctypes::sockaddr_in>() as _ {
                return Err(LinuxError::EINVAL);
            }
            let raw = unsafe { *(addr as *const ctypes::sockaddr_in) };
            Ok(SockAddrValue::Inet(SocketAddr::V4(raw.into())))
        }
        ctypes::AF_UNIX => {
            let raw_len = addrlen as usize;
            let bytes = unsafe { core::slice::from_raw_parts(addr.cast::<u8>(), raw_len) };
            let path = &bytes[UNIX_FAMILY_LEN..];
            let value = if path.is_empty() {
                UnixAddr::Unnamed
            } else if path[0] == 0 {
                UnixAddr::Abstract(path[1..].to_vec())
            } else {
                let end = path.iter().position(|&ch| ch == 0).unwrap_or(path.len());
                let raw_path =
                    core::str::from_utf8(&path[..end]).map_err(|_| LinuxError::EINVAL)?;
                UnixAddr::Path(normalize_unix_path(raw_path)?)
            };
            debug!(
                "    load sockaddr(unix): {:#x} => {:?}",
                addr as usize, value
            );
            Ok(SockAddrValue::Unix(value))
        }
        _ => Err(LinuxError::EAFNOSUPPORT),
    }
}

fn is_supported_socket_domain(domain: u32) -> bool {
    matches!(domain, ctypes::AF_INET | ctypes::AF_UNIX | ctypes::AF_INET6)
}

fn is_valid_socket_type(base_type: u32) -> bool {
    matches!(
        base_type,
        ctypes::SOCK_STREAM | ctypes::SOCK_DGRAM | ctypes::SOCK_RAW | ctypes::SOCK_SEQPACKET
    )
}

fn create_socket(domain: u32, base_type: u32, protocol: u32) -> LinuxResult<Socket> {
    match domain {
        ctypes::AF_INET => match base_type {
            ctypes::SOCK_STREAM => match protocol {
                0 | ctypes::IPPROTO_TCP | ctypes::IPPROTO_SCTP | IPPROTO_SCTP_U32 => {
                    Ok(Socket::new(SocketInner::Tcp(TcpSocket::new())))
                }
                _ => Err(LinuxError::EPROTONOSUPPORT),
            },
            ctypes::SOCK_DGRAM => match protocol {
                0 | ctypes::IPPROTO_UDP | ctypes::IPPROTO_UDPLITE | IPPROTO_UDPLITE_U32 => {
                    Ok(Socket::new(SocketInner::Udp(Mutex::new(UdpSocket::new()))))
                }
                _ => Err(LinuxError::EPROTONOSUPPORT),
            },
            ctypes::SOCK_RAW | ctypes::SOCK_SEQPACKET => Err(LinuxError::EPROTONOSUPPORT),
            _ => Err(LinuxError::EINVAL),
        },
        ctypes::AF_UNIX => match base_type {
            ctypes::SOCK_STREAM if protocol == 0 => Ok(Socket::new(SocketInner::Unix(
                UnixSocket::new(UnixSocketType::Stream),
            ))),
            ctypes::SOCK_SEQPACKET if protocol == 0 => Ok(Socket::new(SocketInner::Unix(
                UnixSocket::new(UnixSocketType::SeqPacket),
            ))),
            ctypes::SOCK_DGRAM if protocol == 0 => Ok(Socket::new(SocketInner::Unix(
                UnixSocket::new(UnixSocketType::Dgram),
            ))),
            ctypes::SOCK_STREAM
            | ctypes::SOCK_DGRAM
            | ctypes::SOCK_SEQPACKET
            | ctypes::SOCK_RAW => Err(LinuxError::EPROTONOSUPPORT),
            _ => Err(LinuxError::EINVAL),
        },
        ctypes::AF_INET6 => Err(LinuxError::EAFNOSUPPORT),
        _ => Err(LinuxError::EAFNOSUPPORT),
    }
}

/// Create an socket for communication.
///
/// Return the socket file descriptor.
pub fn sys_socket(domain: c_int, socktype: c_int, protocol: c_int) -> c_int {
    debug!("sys_socket <= {} {} {}", domain, socktype, protocol);
    let sock_flags = (ctypes::SOCK_NONBLOCK | ctypes::SOCK_CLOEXEC) as u32;
    let (domain, socktype, protocol) = (domain as u32, socktype as u32, protocol as u32);
    syscall_body!(sys_socket, {
        let base_type = socktype & !sock_flags;
        if !is_supported_socket_domain(domain) {
            return Err(LinuxError::EAFNOSUPPORT);
        }
        if !is_valid_socket_type(base_type) {
            return Err(LinuxError::EINVAL);
        }
        let socket = create_socket(domain, base_type, protocol)?;

        if socktype & ctypes::SOCK_NONBLOCK != 0 {
            match &socket.inner {
                SocketInner::Udp(socket) => socket.lock().set_nonblocking(true),
                SocketInner::Tcp(socket) => socket.set_nonblocking(true),
                SocketInner::Unix(socket) => socket.set_nonblocking(true)?,
            }
        }

        let fd_flags = if socktype & ctypes::SOCK_CLOEXEC != 0 {
            FD_CLOEXEC_FLAG
        } else {
            0
        };
        socket.add_to_fd_table_with_flags(fd_flags)
    })
}

pub fn sys_socketpair(domain: c_int, socktype: c_int, protocol: c_int, sv: &mut [c_int]) -> c_int {
    syscall_body!(sys_socketpair, {
        if sv.len() != 2 {
            return Err(LinuxError::EFAULT);
        }
        let sock_flags = (ctypes::SOCK_NONBLOCK | ctypes::SOCK_CLOEXEC) as c_int;
        let base_type = socktype & !sock_flags;
        if !is_supported_socket_domain(domain as u32) {
            return Err(LinuxError::EAFNOSUPPORT);
        }
        if !is_valid_socket_type(base_type as u32) {
            return Err(LinuxError::EINVAL);
        }

        match domain as u32 {
            ctypes::AF_UNIX => {
                if protocol != 0 {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
                if base_type == ctypes::SOCK_RAW as c_int {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
            }
            ctypes::AF_INET => match base_type as u32 {
                ctypes::SOCK_STREAM => match protocol as u32 {
                    0 | ctypes::IPPROTO_TCP | ctypes::IPPROTO_SCTP | IPPROTO_SCTP_U32 => {
                        return Err(LinuxError::EOPNOTSUPP);
                    }
                    _ => return Err(LinuxError::EPROTONOSUPPORT),
                },
                ctypes::SOCK_DGRAM => match protocol as u32 {
                    0 | ctypes::IPPROTO_UDP | ctypes::IPPROTO_UDPLITE | IPPROTO_UDPLITE_U32 => {
                        return Err(LinuxError::EOPNOTSUPP);
                    }
                    _ => return Err(LinuxError::EPROTONOSUPPORT),
                },
                ctypes::SOCK_RAW | ctypes::SOCK_SEQPACKET => {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
                _ => return Err(LinuxError::EINVAL),
            },
            ctypes::AF_INET6 => return Err(LinuxError::EAFNOSUPPORT),
            _ => return Err(LinuxError::EAFNOSUPPORT),
        }

        let (left, right) = SocketPairEndpoint::new_pair();
        if socktype & ctypes::SOCK_NONBLOCK as c_int != 0 {
            left.set_nonblocking(true)?;
            right.set_nonblocking(true)?;
        }
        let fd_flags = if socktype & ctypes::SOCK_CLOEXEC as c_int != 0 {
            FD_CLOEXEC_FLAG
        } else {
            0
        };
        let left_fd = add_file_like_with_fd_flags(Arc::new(left), fd_flags)?;
        let right_fd =
            add_file_like_with_fd_flags(Arc::new(right), fd_flags).inspect_err(|_| {
                super::fd_ops::close_file_like(left_fd).ok();
            })?;

        sv[0] = left_fd;
        sv[1] = right_fd;
        Ok(0)
    })
}

/// Bind a address to a socket.
///
/// Return 0 if success.
pub fn sys_bind(
    socket_fd: c_int,
    socket_addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_bind <= {} {:#x} {}",
        socket_fd, socket_addr as usize, addrlen
    );
    syscall_body!(sys_bind, {
        let addr = from_sockaddr(socket_addr, addrlen)?;
        if let SockAddrValue::Inet(addr) = &addr {
            if axfs::api::current_euid() != 0 && addr.port() < 1024 {
                return Err(LinuxError::EACCES);
            }
            if let SocketAddr::V4(addr_v4) = addr {
                let ip = *addr_v4.ip();
                if ip != Ipv4Addr::UNSPECIFIED && !ip.is_loopback() {
                    return Err(LinuxError::EADDRNOTAVAIL);
                }
            }
        }
        Socket::from_fd(socket_fd)?.bind(addr)?;
        Ok(0)
    })
}

/// Connects the socket to the address specified.
///
/// Return 0 if success.
pub fn sys_connect(
    socket_fd: c_int,
    socket_addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_connect <= {} {:#x} {}",
        socket_fd, socket_addr as usize, addrlen
    );
    syscall_body!(sys_connect, {
        let addr = from_sockaddr(socket_addr, addrlen)?;
        match Socket::from_fd(socket_fd)?.connect(addr) {
            Ok(()) => {}
            Err(LinuxError::EAGAIN) => {
                if axtask::current_wait_should_interrupt() {
                    return Err(LinuxError::EINTR);
                }
                return Err(LinuxError::EINPROGRESS);
            }
            Err(err) => return Err(err.into()),
        }
        Ok(0)
    })
}

/// Send a message on a socket to the address specified.
///
/// Return the number of bytes sent if success.
pub fn sys_sendto(
    socket_fd: c_int,
    buf_ptr: *const c_void,
    len: ctypes::size_t,
    flag: c_int, // currently not used
    socket_addr: *const ctypes::sockaddr,
    addrlen: ctypes::socklen_t,
) -> ctypes::ssize_t {
    debug!(
        "sys_sendto <= {} {:#x} {} {} {:#x} {}",
        socket_fd, buf_ptr as usize, len, flag, socket_addr as usize, addrlen
    );
    syscall_body!(sys_sendto, {
        if buf_ptr.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
        let socket = Socket::from_fd(socket_fd)?;
        if socket_addr.is_null() {
            if addrlen != 0 {
                return Err(LinuxError::EFAULT);
            }
            return socket.send(buf).map_err(|err| {
                if err == LinuxError::EAGAIN && axtask::current_wait_should_interrupt() {
                    LinuxError::EINTR
                } else {
                    err
                }
            });
        }
        let addr = from_sockaddr(socket_addr, addrlen)?;
        socket.sendto(buf, addr).map_err(|err| {
            if err == LinuxError::EAGAIN && axtask::current_wait_should_interrupt() {
                LinuxError::EINTR
            } else {
                err
            }
        })
    })
}

/// Send a message on a socket to the address connected.
///
/// Return the number of bytes sent if success.
pub fn sys_send(
    socket_fd: c_int,
    buf_ptr: *const c_void,
    len: ctypes::size_t,
    flag: c_int, // currently not used
) -> ctypes::ssize_t {
    debug!(
        "sys_sendto <= {} {:#x} {} {}",
        socket_fd, buf_ptr as usize, len, flag
    );
    syscall_body!(sys_send, {
        if buf_ptr.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let buf = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, len) };
        Socket::from_fd(socket_fd)?.send(buf).map_err(|err| {
            if err == LinuxError::EAGAIN && axtask::current_wait_should_interrupt() {
                LinuxError::EINTR
            } else {
                err
            }
        })
    })
}

/// Receive a message on a socket and get its source address.
///
/// Return the number of bytes received if success.
pub unsafe fn sys_recvfrom(
    socket_fd: c_int,
    buf_ptr: *mut c_void,
    len: ctypes::size_t,
    flag: c_int, // currently not used
    socket_addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> ctypes::ssize_t {
    debug!(
        "sys_recvfrom <= {} {:#x} {} {} {:#x} {:#x}",
        socket_fd, buf_ptr as usize, len, flag, socket_addr as usize, addrlen as usize
    );
    syscall_body!(sys_recvfrom, {
        if buf_ptr.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if socket_addr.is_null() != addrlen.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let socket = Socket::from_fd(socket_fd)?;
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
        let res = socket.recvfrom(buf).map_err(|err| {
            if err == LinuxError::EAGAIN && axtask::current_wait_should_interrupt() {
                LinuxError::EINTR
            } else {
                err
            }
        })?;
        if let Some(addr) = res.1.filter(|_| !socket_addr.is_null()) {
            unsafe { copy_sockaddr_to_user(socket_addr, addrlen, addr)? };
        }
        Ok(res.0)
    })
}

/// Receive a message on a socket.
///
/// Return the number of bytes received if success.
pub fn sys_recv(
    socket_fd: c_int,
    buf_ptr: *mut c_void,
    len: ctypes::size_t,
    flag: c_int, // currently not used
) -> ctypes::ssize_t {
    debug!(
        "sys_recv <= {} {:#x} {} {}",
        socket_fd, buf_ptr as usize, len, flag
    );
    syscall_body!(sys_recv, {
        if buf_ptr.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let buf = unsafe { core::slice::from_raw_parts_mut(buf_ptr as *mut u8, len) };
        Socket::from_fd(socket_fd)?.recv(buf).map_err(|err| {
            if err == LinuxError::EAGAIN && axtask::current_wait_should_interrupt() {
                LinuxError::EINTR
            } else {
                err
            }
        })
    })
}

/// Listen for connections on a socket
///
/// Return 0 if success.
pub fn sys_listen(
    socket_fd: c_int,
    backlog: c_int, // currently not used
) -> c_int {
    debug!("sys_listen <= {} {}", socket_fd, backlog);
    syscall_body!(sys_listen, {
        Socket::from_fd(socket_fd)?.listen()?;
        Ok(0)
    })
}

/// Accept for connections on a socket
///
/// Return file descriptor for the accepted socket if success.
pub unsafe fn sys_accept(
    socket_fd: c_int,
    socket_addr: *mut ctypes::sockaddr,
    socket_len: *mut ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_accept <= {} {:#x} {:#x}",
        socket_fd, socket_addr as usize, socket_len as usize
    );
    syscall_body!(sys_accept, {
        if socket_addr.is_null() != socket_len.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let socket = Socket::from_fd(socket_fd)?;
        let new_socket = socket.accept().map_err(|err| {
            if err == LinuxError::EAGAIN && axtask::current_wait_should_interrupt() {
                LinuxError::EINTR
            } else {
                err
            }
        })?;
        let new_fd = new_socket.add_to_fd_table()?;
        if !socket_addr.is_null() {
            let addr = Socket::from_fd(new_fd)?.peer_addr()?;
            unsafe { copy_sockaddr_to_user(socket_addr, socket_len, addr)? };
        }
        Ok(new_fd)
    })
}

/// Shut down a full-duplex connection.
///
/// Return 0 if success.
pub fn sys_shutdown(
    socket_fd: c_int,
    flag: c_int, // currently not used
) -> c_int {
    debug!("sys_shutdown <= {} {}", socket_fd, flag);
    syscall_body!(sys_shutdown, {
        Socket::from_fd(socket_fd)?.shutdown(flag)?;
        Ok(0)
    })
}

/// Query addresses for a domain name.
///
/// Only IPv4. Ports are always 0. Ignore servname and hint.
/// Results' ai_flags and ai_canonname are 0 or NULL.
///
/// Return address number if success.
pub unsafe fn sys_getaddrinfo(
    nodename: *const c_char,
    servname: *const c_char,
    hints: *const ctypes::addrinfo,
    res: *mut *mut ctypes::addrinfo,
) -> c_int {
    let name = char_ptr_to_str(nodename);
    let port = char_ptr_to_str(servname);
    debug!("sys_getaddrinfo <= {:?} {:?}", name, port);
    syscall_body!(sys_getaddrinfo, {
        if nodename.is_null() && servname.is_null() {
            return Ok(0);
        }
        if res.is_null() {
            return Err(LinuxError::EFAULT);
        }

        let port = port.map_or(0, |p| p.parse::<u16>().unwrap_or(0));
        let passive = !hints.is_null() && ((*hints).ai_flags & AI_PASSIVE) != 0;
        let ip_addrs = if let Ok(domain) = name {
            if let Ok(a) = domain.parse::<IpAddr>() {
                vec![a]
            } else {
                axnet::dns_query(domain)?
            }
        } else if passive {
            vec![Ipv4Addr::UNSPECIFIED.into()]
        } else {
            vec![Ipv4Addr::LOCALHOST.into()]
        };

        let len = ip_addrs.len().min(ctypes::MAXADDRS as usize);
        if len == 0 {
            return Ok(0);
        }

        let mut out: Vec<ctypes::aibuf> = Vec::with_capacity(len);
        for (i, &ip) in ip_addrs.iter().enumerate().take(len) {
            let buf = match ip {
                IpAddr::V4(ip) => ctypes::aibuf {
                    ai: ctypes::addrinfo {
                        ai_family: ctypes::AF_INET as _,
                        // TODO: This is a hard-code part, only return TCP parameters
                        ai_socktype: ctypes::SOCK_STREAM as _,
                        ai_protocol: ctypes::IPPROTO_TCP as _,
                        ai_addrlen: size_of::<ctypes::sockaddr_in>() as _,
                        ai_addr: core::ptr::null_mut(),
                        ai_canonname: core::ptr::null_mut(),
                        ai_next: core::ptr::null_mut(),
                        ai_flags: 0,
                    },
                    sa: ctypes::aibuf_sa {
                        sin: SocketAddrV4::new(ip, port).into(),
                    },
                    slot: i as i16,
                    lock: [0],
                    ref_: 0,
                },
                _ => panic!("IPv6 is not supported"),
            };
            out.push(buf);
            out[i].ai.ai_addr =
                unsafe { core::ptr::addr_of_mut!(out[i].sa.sin) as *mut ctypes::sockaddr };
            if i > 0 {
                out[i - 1].ai.ai_next = core::ptr::addr_of_mut!(out[i].ai);
            }
        }

        out[0].ref_ = len as i16;
        unsafe { *res = core::ptr::addr_of_mut!(out[0].ai) };
        core::mem::forget(out); // drop in `sys_freeaddrinfo`
        Ok(len)
    })
}

/// Free queried `addrinfo` struct
pub unsafe fn sys_freeaddrinfo(res: *mut ctypes::addrinfo) {
    if res.is_null() {
        return;
    }
    let aibuf_ptr = res as *mut ctypes::aibuf;
    let len = unsafe { *aibuf_ptr }.ref_ as usize;
    assert!(unsafe { *aibuf_ptr }.slot == 0);
    assert!(len > 0);
    let vec = unsafe { Vec::from_raw_parts(aibuf_ptr, len, len) }; // TODO: lock
    drop(vec);
}

/// Get current address to which the socket sockfd is bound.
pub unsafe fn sys_getsockname(
    sock_fd: c_int,
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_getsockname <= {} {:#x} {:#x}",
        sock_fd, addr as usize, addrlen as usize
    );
    syscall_body!(sys_getsockname, {
        if addr.is_null() || addrlen.is_null() {
            return Err(LinuxError::EFAULT);
        }
        unsafe { copy_sockaddr_to_user(addr, addrlen, Socket::from_fd(sock_fd)?.local_addr()?)? };
        Ok(0)
    })
}

/// Get peer address to which the socket sockfd is connected.
pub unsafe fn sys_getpeername(
    sock_fd: c_int,
    addr: *mut ctypes::sockaddr,
    addrlen: *mut ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_getpeername <= {} {:#x} {:#x}",
        sock_fd, addr as usize, addrlen as usize
    );
    syscall_body!(sys_getpeername, {
        if addr.is_null() || addrlen.is_null() {
            return Err(LinuxError::EFAULT);
        }
        unsafe { copy_sockaddr_to_user(addr, addrlen, Socket::from_fd(sock_fd)?.peer_addr()?)? };
        Ok(0)
    })
}

pub unsafe fn sys_setsockopt(
    socket_fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_setsockopt <= {} level={} optname={}",
        socket_fd, level, optname
    );
    syscall_body!(sys_setsockopt, {
        let socket = Socket::from_fd(socket_fd)?;
        match (level, optname) {
            (SOL_SOCKET, SO_REUSEADDR) => {}
            (SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO) => {
                if optval.is_null() || optlen < size_of::<ctypes::timeval>() as _ {
                    return Err(LinuxError::EINVAL);
                }
                let timeout = unsafe { *(optval as *const ctypes::timeval) };
                if timeout.tv_sec < 0 || timeout.tv_usec < 0 || timeout.tv_usec >= 1_000_000 {
                    return Err(LinuxError::EINVAL);
                }
                let duration = if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                    None
                } else {
                    Some(core::time::Duration::new(
                        timeout.tv_sec as u64,
                        (timeout.tv_usec as u32) * 1_000,
                    ))
                };
                if optname == SO_RCVTIMEO {
                    socket.set_recv_timeout(duration);
                } else {
                    socket.set_send_timeout(duration);
                }
            }
            (SOL_IP, IP_ADD_MEMBERSHIP | MCAST_JOIN_GROUP) => {
                socket.remember_ip_membership(level, optname, optval, optlen)?;
            }
            (SOL_IP, IP_DROP_MEMBERSHIP) => {
                socket.forget_ip_membership(level, IP_ADD_MEMBERSHIP, optval, optlen)?;
            }
            (SOL_IP, MCAST_LEAVE_GROUP) => {
                socket.forget_ip_membership(level, MCAST_JOIN_GROUP, optval, optlen)?;
            }
            _ => {
                let _ = socket;
            }
        }
        Ok(0)
    })
}

pub unsafe fn sys_getsockopt(
    socket_fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut ctypes::socklen_t,
) -> c_int {
    debug!(
        "sys_getsockopt <= {} level={} optname={} optval={:#x} optlen={:#x}",
        socket_fd, level, optname, optval as usize, optlen as usize
    );
    syscall_body!(sys_getsockopt, {
        if optval.is_null() || optlen.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let socket = Socket::from_fd(socket_fd)?;
        let len = unsafe { *optlen as usize };
        if (level, optname) == (IPPROTO_TCP, TCP_INFO) {
            let info = socket.tcp_info()?;
            let ret_len = len.min(size_of::<LinuxTcpInfo>());
            if ret_len > 0 {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        (&info as *const LinuxTcpInfo).cast::<u8>(),
                        optval.cast::<u8>(),
                        ret_len,
                    );
                    *optlen = ret_len as ctypes::socklen_t;
                }
            }
            return Ok(0);
        }
        let ret_len = len.min(size_of::<c_int>());
        if ret_len > 0 {
            let value = socket.getsockopt_value(level, optname).to_ne_bytes();
            unsafe {
                core::ptr::copy_nonoverlapping(value.as_ptr(), optval.cast::<u8>(), ret_len);
                *optlen = ret_len as ctypes::socklen_t;
            }
        }
        Ok(0)
    })
}
