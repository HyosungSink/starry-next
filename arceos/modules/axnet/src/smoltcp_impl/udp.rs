use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use axerrno::{AxError, AxResult, ax_err, ax_err_type};
use axhal::time::monotonic_time;
use axio::PollState;
use axsync::Mutex;
use lazyinit::LazyInit;
use spin::RwLock;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{self, BindError, SendError};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::addr::{UNSPECIFIED_ENDPOINT, from_core_sockaddr, into_core_sockaddr, is_unspecified};
use super::{SOCKET_SET, SocketSetWrapper};

type LocalUdpQueue = Arc<Mutex<VecDeque<(Vec<u8>, IpEndpoint)>>>;

#[derive(Clone)]
struct LocalUdpBinding {
    handle: SocketHandle,
    local_addr: IpEndpoint,
    peer_addr: Option<IpEndpoint>,
    queue: LocalUdpQueue,
}

type LocalUdpBindings = Mutex<BTreeMap<u16, Vec<LocalUdpBinding>>>;

fn local_udp_bindings() -> &'static LocalUdpBindings {
    static LOCAL_UDP_BINDINGS: LazyInit<LocalUdpBindings> = LazyInit::new();
    if let Some(bindings) = LOCAL_UDP_BINDINGS.get() {
        bindings
    } else {
        LOCAL_UDP_BINDINGS.init_once(Mutex::new(BTreeMap::new()))
    }
}

fn is_local_loopback_endpoint(endpoint: IpEndpoint) -> bool {
    super::IP
        .parse::<IpAddr>()
        .ok()
        .is_some_and(|ip| endpoint.addr == super::addr::from_core_ipaddr(ip))
}

/// A UDP socket that provides POSIX-like APIs.
pub struct UdpSocket {
    handle: SocketHandle,
    local_addr: RwLock<Option<IpEndpoint>>,
    peer_addr: RwLock<Option<IpEndpoint>>,
    local_rx_queue: LocalUdpQueue,
    nonblock: AtomicBool,
    recv_timeout_us: AtomicU64,
    send_timeout_us: AtomicU64,
}

impl UdpSocket {
    const NO_TIMEOUT_US: u64 = u64::MAX;

    /// Creates a new UDP socket.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let socket = SocketSetWrapper::new_udp_socket();
        let handle = SOCKET_SET.add(socket);
        Self {
            handle,
            local_addr: RwLock::new(None),
            peer_addr: RwLock::new(None),
            local_rx_queue: Arc::new(Mutex::new(VecDeque::new())),
            nonblock: AtomicBool::new(false),
            recv_timeout_us: AtomicU64::new(Self::NO_TIMEOUT_US),
            send_timeout_us: AtomicU64::new(Self::NO_TIMEOUT_US),
        }
    }

    /// Returns the local address and port, or
    /// [`Err(NotConnected)`](AxError::NotConnected) if not connected.
    pub fn local_addr(&self) -> AxResult<SocketAddr> {
        match self.local_addr.try_read() {
            Some(addr) => addr.map(into_core_sockaddr).ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }

    /// Returns the remote address and port, or
    /// [`Err(NotConnected)`](AxError::NotConnected) if not connected.
    pub fn peer_addr(&self) -> AxResult<SocketAddr> {
        self.remote_endpoint().map(into_core_sockaddr)
    }

    /// Returns whether this socket is in nonblocking mode.
    #[inline]
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Acquire)
    }

    /// Moves this UDP socket into or out of nonblocking mode.
    ///
    /// This will result in `recv`, `recv_from`, `send`, and `send_to`
    /// operations becoming nonblocking, i.e., immediately returning from their
    /// calls. If the IO operation is successful, `Ok` is returned and no
    /// further action is required. If the IO operation could not be completed
    /// and needs to be retried, an error with kind
    /// [`Err(WouldBlock)`](AxError::WouldBlock) is returned.
    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblock.store(nonblocking, Ordering::Release);
    }

    #[inline]
    pub fn set_recv_timeout(&self, timeout: Option<Duration>) {
        self.recv_timeout_us
            .store(timeout_to_us(timeout), Ordering::Release);
    }

    #[inline]
    pub fn set_send_timeout(&self, timeout: Option<Duration>) {
        self.send_timeout_us
            .store(timeout_to_us(timeout), Ordering::Release);
    }

    /// Binds an unbound socket to the given address and port.
    ///
    /// It's must be called before [`send_to`](Self::send_to) and
    /// [`recv_from`](Self::recv_from).
    pub fn bind(&self, mut local_addr: SocketAddr) -> AxResult {
        let mut self_local_addr = self.local_addr.write();

        if local_addr.port() == 0 {
            local_addr.set_port(get_ephemeral_port()?);
        }
        if self_local_addr.is_some() {
            return ax_err!(InvalidInput, "socket bind() failed: already bound");
        }

        let local_endpoint = from_core_sockaddr(local_addr);
        let endpoint = IpListenEndpoint {
            addr: (!is_unspecified(local_endpoint.addr)).then_some(local_endpoint.addr),
            port: local_endpoint.port,
        };
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            socket.bind(endpoint).or_else(|e| match e {
                BindError::InvalidState => ax_err!(AlreadyExists, "socket bind() failed"),
                BindError::Unaddressable => ax_err!(InvalidInput, "socket bind() failed"),
            })
        })?;

        *self_local_addr = Some(local_endpoint);
        self.register_local_binding(local_endpoint, None);
        debug!("UDP socket {}: bound on {}", self.handle, endpoint);
        Ok(())
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    pub fn send_to(&self, buf: &[u8], remote_addr: SocketAddr) -> AxResult<usize> {
        if remote_addr.port() == 0 || remote_addr.ip().is_unspecified() {
            return ax_err!(InvalidInput, "socket send_to() failed: invalid address");
        }
        if self.local_addr.read().is_none() {
            self.bind(into_core_sockaddr(UNSPECIFIED_ENDPOINT))?;
        }
        self.send_impl(buf, from_core_sockaddr(remote_addr))
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    pub fn recv_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        if let Some(packet) = self.try_local_recv(false, None, buf) {
            return packet.map(|(len, src)| (len, into_core_sockaddr(src)));
        }
        let timeout = self.recv_timeout();
        if self.local_addr.read().is_none() {
            return ax_err!(NotConnected, "socket send() failed");
        }
        self.block_on(timeout, || {
            if let Some(packet) = self.try_local_recv(false, None, buf) {
                return packet.map(|(len, src)| (len, into_core_sockaddr(src)));
            }
            SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
                if socket.can_recv() {
                    match socket.recv_slice(buf) {
                        Ok((len, meta)) => Ok((len, into_core_sockaddr(meta.endpoint))),
                        Err(_) => ax_err!(BadState, "socket recv_from() failed"),
                    }
                } else {
                    Err(AxError::WouldBlock)
                }
            })
        })
    }

    /// Receives a single datagram message on the socket, without removing it from
    /// the queue. On success, returns the number of bytes read and the origin.
    pub fn peek_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        if let Some(packet) = self.try_local_recv(true, None, buf) {
            return packet.map(|(len, src)| (len, into_core_sockaddr(src)));
        }
        let timeout = self.recv_timeout();
        if self.local_addr.read().is_none() {
            return ax_err!(NotConnected, "socket send() failed");
        }
        self.block_on(timeout, || {
            if let Some(packet) = self.try_local_recv(true, None, buf) {
                return packet.map(|(len, src)| (len, into_core_sockaddr(src)));
            }
            SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
                if socket.can_recv() {
                    match socket.peek_slice(buf) {
                        Ok((len, meta)) => Ok((len, into_core_sockaddr(meta.endpoint))),
                        Err(_) => ax_err!(BadState, "socket recv_from() failed"),
                    }
                } else {
                    Err(AxError::WouldBlock)
                }
            })
        })
    }

    /// Connects this UDP socket to a remote address, allowing the `send` and
    /// `recv` to be used to send data and also applies filters to only receive
    /// data from the specified address.
    ///
    /// The local port will be generated automatically if the socket is not bound.
    /// It's must be called before [`send`](Self::send) and
    /// [`recv`](Self::recv).
    pub fn connect(&self, addr: SocketAddr) -> AxResult {
        let mut self_peer_addr = self.peer_addr.write();

        if self.local_addr.read().is_none() {
            self.bind(into_core_sockaddr(UNSPECIFIED_ENDPOINT))?;
        }

        *self_peer_addr = Some(from_core_sockaddr(addr));
        if let Ok(local_addr) = self.local_endpoint() {
            self.register_local_binding(local_addr, *self_peer_addr);
        }
        debug!("UDP socket {}: connected to {}", self.handle, addr);
        Ok(())
    }

    /// Sends data on the socket to the remote address to which it is connected.
    pub fn send(&self, buf: &[u8]) -> AxResult<usize> {
        let remote_endpoint = self.remote_endpoint()?;
        self.send_impl(buf, remote_endpoint)
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    pub fn recv(&self, buf: &mut [u8]) -> AxResult<usize> {
        let remote_endpoint = self.remote_endpoint()?;
        if let Some(packet) = self.try_local_recv(false, Some(remote_endpoint), buf) {
            return packet.map(|(len, _)| len);
        }
        let timeout = self.recv_timeout();
        if self.local_addr.read().is_none() {
            return ax_err!(NotConnected, "socket send() failed");
        }
        self.block_on(timeout, || {
            if let Some(packet) = self.try_local_recv(false, Some(remote_endpoint), buf) {
                return packet.map(|(len, _)| len);
            }
            SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
                if socket.can_recv() {
                    let (len, meta) = socket
                        .recv_slice(buf)
                        .map_err(|_| ax_err_type!(BadState, "socket recv() failed"))?;
                    if !is_unspecified(remote_endpoint.addr)
                        && remote_endpoint.addr != meta.endpoint.addr
                    {
                        return Err(AxError::WouldBlock);
                    }
                    if remote_endpoint.port != 0 && remote_endpoint.port != meta.endpoint.port {
                        return Err(AxError::WouldBlock);
                    }
                    Ok(len)
                } else {
                    Err(AxError::WouldBlock)
                }
            })
        })
    }

    /// Close the socket.
    pub fn shutdown(&self) -> AxResult {
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            debug!("UDP socket {}: shutting down", self.handle);
            socket.close();
        });
        self.unregister_local_binding();
        self.local_rx_queue.lock().clear();
        SOCKET_SET.poll_interfaces();
        Ok(())
    }

    /// Whether the socket is readable or writable.
    pub fn poll(&self) -> AxResult<PollState> {
        if self.local_addr.read().is_none() {
            return Ok(PollState {
                readable: false,
                writable: false,
            });
        }
        if self.try_local_queue_ready() {
            return Ok(PollState {
                readable: true,
                writable: true,
            });
        }
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            Ok(PollState {
                readable: socket.can_recv(),
                writable: socket.can_send(),
            })
        })
    }
}

/// Private methods
impl UdpSocket {
    fn local_endpoint(&self) -> AxResult<IpEndpoint> {
        self.local_addr
            .try_read()
            .and_then(|addr| *addr)
            .ok_or(AxError::NotConnected)
    }

    fn remote_endpoint(&self) -> AxResult<IpEndpoint> {
        match self.peer_addr.try_read() {
            Some(addr) => addr.ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }

    fn try_local_queue_ready(&self) -> bool {
        if self.local_addr.read().is_none() {
            return false;
        }
        !self.local_rx_queue.lock().is_empty()
    }

    fn try_local_recv(
        &self,
        peek: bool,
        remote_filter: Option<IpEndpoint>,
        buf: &mut [u8],
    ) -> Option<AxResult<(usize, IpEndpoint)>> {
        (*self.local_addr.read())?;
        let mut queue = self.local_rx_queue.lock();
        let idx = queue.iter().position(|(_, src)| {
            if let Some(remote) = remote_filter {
                (is_unspecified(remote.addr) || remote.addr == src.addr)
                    && (remote.port == 0 || remote.port == src.port)
            } else {
                true
            }
        })?;
        let (data, src) = if peek {
            let (data, src) = &queue[idx];
            (data.clone(), *src)
        } else {
            queue.remove(idx).unwrap()
        };
        let len = buf.len().min(data.len());
        buf[..len].copy_from_slice(&data[..len]);
        Some(Ok((len, src)))
    }

    fn send_impl(&self, buf: &[u8], remote_endpoint: IpEndpoint) -> AxResult<usize> {
        let mut local_endpoint = match self.local_endpoint() {
            Ok(local) => local,
            Err(_) => return ax_err!(NotConnected, "socket send() failed"),
        };
        if is_unspecified(local_endpoint.addr) {
            if let Ok(ip) = super::IP.parse::<IpAddr>() {
                local_endpoint.addr = super::addr::from_core_ipaddr(ip);
            }
        }

        if is_local_loopback_endpoint(remote_endpoint) {
            enqueue_local_udp_packet(remote_endpoint, local_endpoint, buf);
            return Ok(buf.len());
        }

        self.block_on(self.send_timeout(), || {
            let len = SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
                if socket.can_send() {
                    socket
                        .send_slice(buf, remote_endpoint)
                        .map_err(|e| match e {
                            SendError::BufferFull => AxError::WouldBlock,
                            SendError::Unaddressable => {
                                ax_err_type!(ConnectionRefused, "socket send() failed")
                            }
                        })?;
                    Ok(buf.len())
                } else {
                    // tx buffer is full
                    Err(AxError::WouldBlock)
                }
            })?;
            SOCKET_SET.poll_interfaces();
            Ok(len)
        })
    }

    fn recv_timeout(&self) -> Option<Duration> {
        timeout_from_us(self.recv_timeout_us.load(Ordering::Acquire))
    }

    fn send_timeout(&self) -> Option<Duration> {
        timeout_from_us(self.send_timeout_us.load(Ordering::Acquire))
    }

    fn block_on<F, T>(&self, timeout: Option<Duration>, mut f: F) -> AxResult<T>
    where
        F: FnMut() -> AxResult<T>,
    {
        if self.is_nonblocking() {
            f()
        } else {
            let deadline = timeout.map(|t| monotonic_time() + t);
            loop {
                match f() {
                    Ok(t) => return Ok(t),
                    Err(AxError::WouldBlock) => {
                        if deadline.is_some_and(|ddl| monotonic_time() >= ddl) {
                            return Err(AxError::WouldBlock);
                        }
                        if axtask::current_wait_should_interrupt() {
                            return Err(AxError::WouldBlock);
                        }
                        if SOCKET_SET.poll_interfaces() {
                            axtask::yield_now();
                        } else {
                            axtask::sleep(Duration::from_millis(1));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    fn register_local_binding(&self, local_addr: IpEndpoint, peer_addr: Option<IpEndpoint>) {
        let mut bindings = local_udp_bindings().lock();
        let entries = bindings.entry(local_addr.port).or_insert_with(Vec::new);
        if let Some(entry) = entries.iter_mut().find(|entry| entry.handle == self.handle) {
            entry.local_addr = local_addr;
            entry.peer_addr = peer_addr;
            entry.queue = self.local_rx_queue.clone();
        } else {
            entries.push(LocalUdpBinding {
                handle: self.handle,
                local_addr,
                peer_addr,
                queue: self.local_rx_queue.clone(),
            });
        }
    }

    fn unregister_local_binding(&self) {
        let mut bindings = local_udp_bindings().lock();
        bindings.retain(|_, entries| {
            entries.retain(|entry| entry.handle != self.handle);
            !entries.is_empty()
        });
    }
}

fn timeout_to_us(timeout: Option<Duration>) -> u64 {
    timeout
        .map(|duration| {
            let micros = duration.as_micros();
            micros.min((u64::MAX - 1) as u128) as u64
        })
        .unwrap_or(UdpSocket::NO_TIMEOUT_US)
}

fn timeout_from_us(timeout_us: u64) -> Option<Duration> {
    (timeout_us != UdpSocket::NO_TIMEOUT_US).then(|| Duration::from_micros(timeout_us))
}

fn endpoint_matches(bound: IpEndpoint, target: IpEndpoint) -> bool {
    bound.port == target.port && (is_unspecified(bound.addr) || bound.addr == target.addr)
}

fn peer_matches(peer: IpEndpoint, source: IpEndpoint) -> bool {
    (is_unspecified(peer.addr) || peer.addr == source.addr)
        && (peer.port == 0 || peer.port == source.port)
}

fn enqueue_local_udp_packet(target: IpEndpoint, source: IpEndpoint, buf: &[u8]) {
    let queue = {
        let bindings = local_udp_bindings().lock();
        bindings.get(&target.port).and_then(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    if !endpoint_matches(entry.local_addr, target) {
                        return None;
                    }
                    let local_score = (!is_unspecified(entry.local_addr.addr)) as u8;
                    match entry.peer_addr {
                        Some(peer) if peer_matches(peer, source) => {
                            Some((entry.queue.clone(), 2 + local_score))
                        }
                        Some(_) => None,
                        None => Some((entry.queue.clone(), local_score)),
                    }
                })
                .max_by_key(|(_, score)| *score)
                .map(|(queue, _)| queue)
        })
    };

    if let Some(queue) = queue {
        queue.lock().push_back((buf.to_vec(), source));
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.shutdown().ok();
        SOCKET_SET.remove(self.handle);
    }
}

fn get_ephemeral_port() -> AxResult<u16> {
    const PORT_START: u16 = 0xc000;
    const PORT_END: u16 = 0xffff;
    static CURR: Mutex<u16> = Mutex::new(PORT_START);
    let mut curr = CURR.lock();

    let port = *curr;
    if *curr == PORT_END {
        *curr = PORT_START;
    } else {
        *curr += 1;
    }
    Ok(port)
}
