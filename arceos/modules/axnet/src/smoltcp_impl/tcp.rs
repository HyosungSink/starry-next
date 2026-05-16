use core::cell::UnsafeCell;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use core::time::Duration;

use axerrno::{AxError, AxResult, ax_err, ax_err_type};
use axhal::time::monotonic_time;
use axio::PollState;
use axsync::Mutex;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::AnySocket;
use smoltcp::socket::tcp::{self, ConnectError, State};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use super::addr::{UNSPECIFIED_ENDPOINT, from_core_sockaddr, into_core_sockaddr, is_unspecified};
use super::{ETH0, LISTEN_TABLE, SOCKET_SET, SocketSetWrapper, queue_tcp_zombie};

// State transitions:
// CLOSED -(connect)-> BUSY -> CONNECTING -> CONNECTED -(shutdown)-> BUSY -> CLOSED
//       |
//       |-(listen)-> BUSY -> LISTENING -(shutdown)-> BUSY -> CLOSED
//       |
//        -(bind)-> BUSY -> CLOSED
const STATE_CLOSED: u8 = 0;
const STATE_BUSY: u8 = 1;
const STATE_CONNECTING: u8 = 2;
const STATE_CONNECTED: u8 = 3;
const STATE_LISTENING: u8 = 4;

const SHUTDOWN_READ: u8 = 1;
const SHUTDOWN_WRITE: u8 = 2;

#[derive(Clone, Copy)]
pub enum Shutdown {
    Read,
    Write,
    ReadWrite,
}

/// A TCP socket that provides POSIX-like APIs.
///
/// - [`connect`] is for TCP clients.
/// - [`bind`], [`listen`], and [`accept`] are for TCP servers.
/// - Other methods are for both TCP clients and servers.
///
/// [`connect`]: TcpSocket::connect
/// [`bind`]: TcpSocket::bind
/// [`listen`]: TcpSocket::listen
/// [`accept`]: TcpSocket::accept
pub struct TcpSocket {
    state: AtomicU8,
    shutdown: AtomicU8,
    handle: UnsafeCell<Option<SocketHandle>>,
    local_addr: UnsafeCell<IpEndpoint>,
    peer_addr: UnsafeCell<IpEndpoint>,
    nonblock: AtomicBool,
    recv_timeout_us: AtomicU64,
    send_timeout_us: AtomicU64,
}

unsafe impl Sync for TcpSocket {}

impl TcpSocket {
    const NO_TIMEOUT_US: u64 = u64::MAX;

    /// Creates a new TCP socket.
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            shutdown: AtomicU8::new(0),
            handle: UnsafeCell::new(None),
            local_addr: UnsafeCell::new(UNSPECIFIED_ENDPOINT),
            peer_addr: UnsafeCell::new(UNSPECIFIED_ENDPOINT),
            nonblock: AtomicBool::new(false),
            recv_timeout_us: AtomicU64::new(Self::NO_TIMEOUT_US),
            send_timeout_us: AtomicU64::new(Self::NO_TIMEOUT_US),
        }
    }

    /// Creates a new TCP socket that is already connected.
    const fn new_connected(
        handle: SocketHandle,
        local_addr: IpEndpoint,
        peer_addr: IpEndpoint,
    ) -> Self {
        Self {
            state: AtomicU8::new(STATE_CONNECTED),
            shutdown: AtomicU8::new(0),
            handle: UnsafeCell::new(Some(handle)),
            local_addr: UnsafeCell::new(local_addr),
            peer_addr: UnsafeCell::new(peer_addr),
            nonblock: AtomicBool::new(false),
            recv_timeout_us: AtomicU64::new(Self::NO_TIMEOUT_US),
            send_timeout_us: AtomicU64::new(Self::NO_TIMEOUT_US),
        }
    }

    /// Returns the local address and port, or
    /// [`Err(NotConnected)`](AxError::NotConnected) if not connected.
    #[inline]
    pub fn local_addr(&self) -> AxResult<SocketAddr> {
        let local_addr = unsafe { self.local_addr.get().read() };
        match self.get_state() {
            STATE_CONNECTED | STATE_LISTENING => Ok(into_core_sockaddr(local_addr)),
            STATE_CLOSED if local_addr != UNSPECIFIED_ENDPOINT => {
                Ok(into_core_sockaddr(local_addr))
            }
            _ => Err(AxError::NotConnected),
        }
    }

    /// Returns the remote address and port, or
    /// [`Err(NotConnected)`](AxError::NotConnected) if not connected.
    #[inline]
    pub fn peer_addr(&self) -> AxResult<SocketAddr> {
        match self.get_state() {
            STATE_CONNECTED | STATE_LISTENING => {
                Ok(into_core_sockaddr(unsafe { self.peer_addr.get().read() }))
            }
            _ => Err(AxError::NotConnected),
        }
    }

    /// Returns whether this socket is in nonblocking mode.
    #[inline]
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Acquire)
    }

    /// Moves this TCP stream into or out of nonblocking mode.
    ///
    /// This will result in `read`, `write`, `recv` and `send` operations
    /// becoming nonblocking, i.e., immediately returning from their calls.
    /// If the IO operation is successful, `Ok` is returned and no further
    /// action is required. If the IO operation could not be completed and needs
    /// to be retried, an error with kind  [`Err(WouldBlock)`](AxError::WouldBlock) is
    /// returned.
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

    /// Connects to the given address and port.
    ///
    /// The local port is generated automatically.
    pub fn connect(&self, remote_addr: SocketAddr) -> AxResult {
        self.update_state(STATE_CLOSED, STATE_CONNECTING, || {
            self.begin_connect(remote_addr)
        })
        .unwrap_or_else(|_| ax_err!(AlreadyExists, "socket connect() failed: already connected"))?; // EISCONN

        // Here our state must be `CONNECTING`, and only one thread can run here.
        if self.is_nonblocking() {
            Err(AxError::WouldBlock)
        } else {
            let retry_deadline = monotonic_time() + Duration::from_millis(50);
            self.block_on(None, || {
                let PollState { writable, .. } = self.poll_connect()?;
                if !writable {
                    Err(AxError::WouldBlock)
                } else if self.get_state() == STATE_CONNECTED {
                    Ok(())
                } else if monotonic_time() < retry_deadline {
                    match self.update_state(STATE_CLOSED, STATE_CONNECTING, || {
                        self.begin_connect(remote_addr)
                    }) {
                        Ok(Ok(())) => Err(AxError::WouldBlock),
                        Ok(Err(e)) => Err(e),
                        Err(_) => ax_err!(ConnectionRefused, "socket connect() failed"),
                    }
                } else {
                    ax_err!(ConnectionRefused, "socket connect() failed")
                }
            })
        }
    }

    /// Binds an unbound socket to the given address and port.
    ///
    /// If the given port is 0, it generates one automatically.
    ///
    /// It's must be called before [`listen`](Self::listen) and
    /// [`accept`](Self::accept).
    pub fn bind(&self, mut local_addr: SocketAddr) -> AxResult {
        self.update_state(STATE_CLOSED, STATE_CLOSED, || {
            // TODO: check addr is available
            if local_addr.port() == 0 {
                local_addr.set_port(get_ephemeral_port()?);
            }
            // SAFETY: no other threads can read or write `self.local_addr` as we
            // have changed the state to `BUSY`.
            unsafe {
                let old = self.local_addr.get().read();
                if old != UNSPECIFIED_ENDPOINT {
                    return ax_err!(InvalidInput, "socket bind() failed: already bound");
                }
                self.local_addr.get().write(from_core_sockaddr(local_addr));
            }
            Ok(())
        })
        .unwrap_or_else(|_| ax_err!(InvalidInput, "socket bind() failed: already bound"))
    }

    /// Starts listening on the bound address and port.
    ///
    /// It's must be called after [`bind`](Self::bind) and before
    /// [`accept`](Self::accept).
    pub fn listen(&self) -> AxResult {
        self.update_state(STATE_CLOSED, STATE_LISTENING, || {
            let bound_endpoint = self.bound_endpoint()?;
            unsafe {
                (*self.local_addr.get()).port = bound_endpoint.port;
            }
            LISTEN_TABLE.listen(bound_endpoint)?;
            debug!("TCP socket listening on {}", bound_endpoint);
            Ok(())
        })
        .unwrap_or(Ok(())) // ignore simultaneous `listen`s.
    }

    /// Accepts a new connection.
    ///
    /// This function will block the calling thread until a new TCP connection
    /// is established. When established, a new [`TcpSocket`] is returned.
    ///
    /// It's must be called after [`bind`](Self::bind) and [`listen`](Self::listen).
    pub fn accept(&self) -> AxResult<TcpSocket> {
        if !self.is_listening() {
            return Err(AxError::InvalidInput);
        }

        // SAFETY: `self.local_addr` should be initialized after `bind()`.
        let local_port = unsafe { self.local_addr.get().read().port };
        self.block_on(None, || {
            let (handle, (local_addr, peer_addr)) = LISTEN_TABLE.accept(local_port)?;
            debug!("TCP socket accepted a new connection {}", peer_addr);
            Ok(TcpSocket::new_connected(handle, local_addr, peer_addr))
        })
    }

    /// Close the connection.
    pub fn shutdown(&self, how: Shutdown) -> AxResult {
        // stream
        if self.is_connected() {
            // SAFETY: `self.handle` should be initialized in a connected socket.
            let handle = unsafe { self.handle.get().read().unwrap() };
            let mut flags = 0;
            match how {
                Shutdown::Read => flags |= SHUTDOWN_READ,
                Shutdown::Write => flags |= SHUTDOWN_WRITE,
                Shutdown::ReadWrite => flags |= SHUTDOWN_READ | SHUTDOWN_WRITE,
            }
            self.shutdown.fetch_or(flags, Ordering::AcqRel);
            if flags & SHUTDOWN_WRITE != 0 {
                SOCKET_SET.with_socket_mut::<tcp::Socket, _, _>(handle, |socket| {
                    debug!("TCP socket {}: shutting down write half", handle);
                    socket.close();
                });
                SOCKET_SET.poll_interfaces();
            }
            return Ok(());
        }

        // listener
        self.update_state(STATE_LISTENING, STATE_CLOSED, || {
            // SAFETY: `self.local_addr` should be initialized in a listening socket,
            // and no other threads can read or write it.
            let local_port = unsafe { self.local_addr.get().read().port };
            unsafe { self.local_addr.get().write(UNSPECIFIED_ENDPOINT) }; // clear bound address
            LISTEN_TABLE.unlisten(local_port);
            SOCKET_SET.poll_interfaces();
            Ok(())
        })
        .unwrap_or(Ok(()))?;

        // ignore for other states
        Ok(())
    }

    /// Receives data from the socket, stores it in the given buffer.
    pub fn recv(&self, buf: &mut [u8]) -> AxResult<usize> {
        if self.is_connecting() {
            return Err(AxError::WouldBlock);
        } else if !self.is_connected() {
            return ax_err!(NotConnected, "socket recv() failed");
        } else if self.is_shutdown_read() {
            return Ok(0);
        }

        // SAFETY: `self.handle` should be initialized in a connected socket.
        let handle = unsafe { self.handle.get().read().unwrap() };
        let len = self.block_on(self.recv_timeout(), || {
            SOCKET_SET.with_socket_mut::<tcp::Socket, _, _>(handle, |socket| {
                if socket.recv_queue() > 0 {
                    // data available
                    // TODO: use socket.recv(|buf| {...})
                    let len = socket
                        .recv_slice(buf)
                        .map_err(|_| ax_err_type!(BadState, "socket recv() failed"))?;
                    Ok(len)
                } else if !socket.may_recv() || !socket.is_active() {
                    Ok(0)
                } else {
                    // no more data
                    Err(AxError::WouldBlock)
                }
            })
        })?;
        SOCKET_SET.poll_interfaces();
        Ok(len)
    }

    /// Transmits data in the given buffer.
    pub fn send(&self, buf: &[u8]) -> AxResult<usize> {
        if self.is_connecting() {
            return Err(AxError::WouldBlock);
        } else if !self.is_connected() {
            return ax_err!(NotConnected, "socket send() failed");
        } else if self.is_shutdown_write() {
            return ax_err!(ConnectionReset, "socket send() failed");
        }

        // SAFETY: `self.handle` should be initialized in a connected socket.
        let handle = unsafe { self.handle.get().read().unwrap() };
        let len = self.block_on(self.send_timeout(), || {
            SOCKET_SET.with_socket_mut::<tcp::Socket, _, _>(handle, |socket| {
                if !socket.is_active() || !socket.may_send() {
                    // closed by remote
                    ax_err!(ConnectionReset, "socket send() failed")
                } else if socket.can_send() {
                    // connected, and the tx buffer is not full
                    // TODO: use socket.send(|buf| {...})
                    let len = socket
                        .send_slice(buf)
                        .map_err(|_| ax_err_type!(BadState, "socket send() failed"))?;
                    Ok(len)
                } else {
                    // tx buffer is full
                    Err(AxError::WouldBlock)
                }
            })
        })?;
        SOCKET_SET.poll_interfaces();
        Ok(len)
    }

    /// Whether the socket is readable or writable.
    pub fn poll(&self) -> AxResult<PollState> {
        match self.get_state() {
            STATE_CONNECTING => self.poll_connect(),
            STATE_CONNECTED => self.poll_stream(),
            STATE_LISTENING => self.poll_listener(),
            _ => Ok(PollState {
                readable: false,
                writable: false,
            }),
        }
    }
}

/// Private methods
impl TcpSocket {
    #[inline]
    fn get_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    #[inline]
    fn set_state(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }

    /// Update the state of the socket atomically.
    ///
    /// If the current state is `expect`, it first changes the state to `STATE_BUSY`,
    /// then calls the given function. If the function returns `Ok`, it changes the
    /// state to `new`, otherwise it changes the state back to `expect`.
    ///
    /// It returns `Ok` if the current state is `expect`, otherwise it returns
    /// the current state in `Err`.
    fn update_state<F, T>(&self, expect: u8, new: u8, f: F) -> Result<AxResult<T>, u8>
    where
        F: FnOnce() -> AxResult<T>,
    {
        match self
            .state
            .compare_exchange(expect, STATE_BUSY, Ordering::Acquire, Ordering::Acquire)
        {
            Ok(_) => {
                let res = f();
                if res.is_ok() {
                    self.set_state(new);
                } else {
                    self.set_state(expect);
                }
                Ok(res)
            }
            Err(old) => Err(old),
        }
    }

    #[inline]
    fn is_connecting(&self) -> bool {
        self.get_state() == STATE_CONNECTING
    }

    #[inline]
    fn is_connected(&self) -> bool {
        self.get_state() == STATE_CONNECTED
    }

    #[inline]
    fn is_listening(&self) -> bool {
        self.get_state() == STATE_LISTENING
    }

    #[inline]
    fn shutdown_flags(&self) -> u8 {
        self.shutdown.load(Ordering::Acquire)
    }

    #[inline]
    fn is_shutdown_read(&self) -> bool {
        self.shutdown_flags() & SHUTDOWN_READ != 0
    }

    #[inline]
    fn is_shutdown_write(&self) -> bool {
        self.shutdown_flags() & SHUTDOWN_WRITE != 0
    }

    fn bound_endpoint(&self) -> AxResult<IpListenEndpoint> {
        // SAFETY: no other threads can read or write `self.local_addr`.
        let local_addr = unsafe { self.local_addr.get().read() };
        let port = if local_addr.port != 0 {
            local_addr.port
        } else {
            get_ephemeral_port()?
        };
        assert_ne!(port, 0);
        let addr = if !is_unspecified(local_addr.addr) {
            Some(local_addr.addr)
        } else {
            None
        };
        Ok(IpListenEndpoint { addr, port })
    }

    fn begin_connect(&self, remote_addr: SocketAddr) -> AxResult {
        // SAFETY: no other threads can read or write these fields.
        let handle = if let Some(old_handle) = unsafe { self.handle.get().read() } {
            queue_tcp_zombie(old_handle);
            SOCKET_SET.add(SocketSetWrapper::new_tcp_socket())
        } else {
            SOCKET_SET.add(SocketSetWrapper::new_tcp_socket())
        };

        let remote_endpoint = from_core_sockaddr(remote_addr);
        let bound_endpoint = self.bound_endpoint()?;
        let iface = &ETH0.iface;
        let (local_endpoint, remote_endpoint) =
            SOCKET_SET.with_socket_mut::<tcp::Socket, _, _>(handle, |socket| {
                socket
                    .connect(iface.lock().context(), remote_endpoint, bound_endpoint)
                    .or_else(|e| match e {
                        ConnectError::InvalidState => {
                            ax_err!(BadState, "socket connect() failed")
                        }
                        ConnectError::Unaddressable => {
                            ax_err!(ConnectionRefused, "socket connect() failed")
                        }
                    })?;
                Ok((
                    socket.local_endpoint().unwrap(),
                    socket.remote_endpoint().unwrap(),
                ))
            })?;
        unsafe {
            self.local_addr.get().write(local_endpoint);
            self.peer_addr.get().write(remote_endpoint);
            self.handle.get().write(Some(handle));
        }
        self.shutdown.store(0, Ordering::Release);
        Ok(())
    }

    fn poll_connect(&self) -> AxResult<PollState> {
        // SAFETY: `self.handle` should be initialized above.
        let handle = unsafe { self.handle.get().read().unwrap() };
        let writable =
            SOCKET_SET.with_socket::<tcp::Socket, _, _>(handle, |socket| match socket.state() {
                State::SynSent => false, // wait for connection
                State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
                | State::TimeWait => {
                    self.set_state(STATE_CONNECTED); // connected
                    debug!(
                        "TCP socket {}: connect completed in state {:?} to {}",
                        handle,
                        socket.state(),
                        socket.remote_endpoint().unwrap(),
                    );
                    true
                }
                _ => {
                    warn!(
                        "TCP socket {} connect failed in state {:?}",
                        handle,
                        socket.state()
                    );
                    unsafe {
                        self.local_addr.get().write(UNSPECIFIED_ENDPOINT);
                        self.peer_addr.get().write(UNSPECIFIED_ENDPOINT);
                    }
                    self.set_state(STATE_CLOSED); // connection failed
                    true
                }
            });
        Ok(PollState {
            readable: false,
            writable,
        })
    }

    fn poll_stream(&self) -> AxResult<PollState> {
        // SAFETY: `self.handle` should be initialized in a connected socket.
        let handle = unsafe { self.handle.get().read().unwrap() };
        SOCKET_SET.with_socket::<tcp::Socket, _, _>(handle, |socket| {
            Ok(PollState {
                readable: self.is_shutdown_read()
                    || socket.recv_queue() > 0
                    || !socket.may_recv()
                    || !socket.is_active(),
                writable: !self.is_shutdown_write() && socket.can_send(),
            })
        })
    }

    fn poll_listener(&self) -> AxResult<PollState> {
        // SAFETY: `self.local_addr` should be initialized in a listening socket.
        let local_addr = unsafe { self.local_addr.get().read() };
        Ok(PollState {
            readable: LISTEN_TABLE.can_accept(local_addr.port)?,
            writable: false,
        })
    }

    /// Block the current thread until the given function completes or fails.
    ///
    /// If the socket is non-blocking, it calls the function once and returns
    /// immediately. Otherwise, it may call the function multiple times if it
    /// returns [`Err(WouldBlock)`](AxError::WouldBlock).
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
}

fn timeout_to_us(timeout: Option<Duration>) -> u64 {
    timeout
        .map(|duration| {
            let micros = duration.as_micros();
            micros.min((u64::MAX - 1) as u128) as u64
        })
        .unwrap_or(TcpSocket::NO_TIMEOUT_US)
}

fn timeout_from_us(timeout_us: u64) -> Option<Duration> {
    (timeout_us != TcpSocket::NO_TIMEOUT_US).then(|| Duration::from_micros(timeout_us))
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        self.shutdown(Shutdown::ReadWrite).ok();
        // Safe because we have mut reference to `self`.
        if let Some(handle) = unsafe { self.handle.get().read() } {
            let drain_deadline = monotonic_time() + Duration::from_millis(20);
            let mut should_remove_now =
                SOCKET_SET.with_socket::<tcp::Socket, _, _>(handle, |socket| !socket.is_open());
            while !should_remove_now && monotonic_time() < drain_deadline {
                let net_progress = SOCKET_SET.poll_interfaces();
                should_remove_now =
                    SOCKET_SET.with_socket::<tcp::Socket, _, _>(handle, |socket| !socket.is_open());
                if !should_remove_now {
                    if net_progress {
                        axtask::yield_now();
                    } else {
                        axtask::sleep(Duration::from_millis(1));
                    }
                }
            }
            if should_remove_now {
                SOCKET_SET.remove(handle);
            } else {
                queue_tcp_zombie(handle);
                SOCKET_SET.poll_interfaces();
            }
        }
    }
}

fn get_ephemeral_port() -> AxResult<u16> {
    const PORT_START: u16 = 0xc000;
    const PORT_END: u16 = 0xffff;
    static CURR: Mutex<u16> = Mutex::new(PORT_START);

    let mut curr = CURR.lock();
    let mut tries = 0;
    while tries <= PORT_END - PORT_START {
        let port = *curr;
        if *curr == PORT_END {
            *curr = PORT_START;
        } else {
            *curr += 1;
        }
        if port_is_available(port) {
            return Ok(port);
        }
        tries += 1;
    }
    ax_err!(AddrInUse, "no avaliable ports!")
}

fn port_is_available(port: u16) -> bool {
    if !LISTEN_TABLE.can_listen(port) {
        return false;
    }
    SOCKET_SET.with_set(|set| {
        !set.iter().any(|(_, socket)| {
            tcp::Socket::downcast(socket).is_some_and(|socket| {
                socket.is_open()
                    && socket
                        .local_endpoint()
                        .is_some_and(|endpoint| endpoint.port == port)
            })
        })
    })
}
