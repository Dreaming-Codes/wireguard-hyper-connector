//! Userspace TCP/IP network stack using smoltcp.
//!
//! This module provides a TCP/IP stack that runs entirely in userspace,
//! routing packets through our WireGuard tunnel.

use crate::error::{Error, Result};
use crate::wireguard::WireGuardTunnel;
use bytes::BytesMut;
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Packet, TcpPacket};
use std::collections::VecDeque;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// MTU for the virtual interface.
/// Some networks drop large UDP packets, especially when WireGuard overhead is added.
/// We use a conservative MTU that results in ~600 byte UDP packets after WireGuard
/// encapsulation (MTU + 40 IP/TCP headers + 48 WG overhead ≈ 548 byte UDP).
/// This works around networks that filter large UDP packets.
const MTU: usize = 460;

/// Size of TCP socket buffers.
const TCP_BUFFER_SIZE: usize = 65535;

/// A virtual network device that sends/receives through the WireGuard tunnel.
struct VirtualDevice {
    /// Packets ready to be received by smoltcp (from WireGuard).
    rx_queue: VecDeque<BytesMut>,
    /// Packets ready to be sent (to WireGuard).
    tx_queue: VecDeque<BytesMut>,
}

impl VirtualDevice {
    fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }

    /// Add a packet to the receive queue (from WireGuard).
    fn push_rx(&mut self, packet: BytesMut) {
        self.rx_queue.push_back(packet);
    }

    /// Take all packets from the transmit queue (to send via WireGuard).
    fn drain_tx(&mut self) -> Vec<BytesMut> {
        self.tx_queue.drain(..).collect()
    }
}

/// RxToken for smoltcp.
struct VirtualRxToken {
    buffer: BytesMut,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

/// TxToken for smoltcp.
struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<BytesMut>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = BytesMut::zeroed(len);
        let result = f(&mut buffer);
        self.tx_queue.push_back(buffer);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.rx_queue.pop_front() {
            Some((
                VirtualRxToken { buffer },
                VirtualTxToken {
                    tx_queue: &mut self.tx_queue,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

/// Shared state for the network stack.
struct NetStackInner {
    interface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
}

/// A userspace TCP/IP network stack.
pub struct NetStack {
    inner: Mutex<NetStackInner>,
    wg_tunnel: Arc<WireGuardTunnel>,
    /// Sender to queue packets for transmission through WireGuard.
    wg_tx: mpsc::Sender<BytesMut>,
}

impl NetStack {
    /// Create a new network stack backed by a WireGuard tunnel.
    pub fn new(wg_tunnel: Arc<WireGuardTunnel>) -> Arc<Self> {
        let tunnel_ip = wg_tunnel.tunnel_ip();
        let wg_tx = wg_tunnel.outgoing_sender();

        // Create the virtual device
        let mut device = VirtualDevice::new();

        // Create the interface configuration
        let config = Config::new(HardwareAddress::Ip);

        // Create the interface
        let mut interface = Interface::new(config, &mut device, Instant::now());

        // Configure the interface with our tunnel IP
        interface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::v4(
                        tunnel_ip.octets()[0],
                        tunnel_ip.octets()[1],
                        tunnel_ip.octets()[2],
                        tunnel_ip.octets()[3],
                    ),
                    32,
                ))
                .unwrap();
        });

        // Set up routing - route everything through this interface
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 0))
            .unwrap();

        // Create socket set
        let sockets = SocketSet::new(vec![]);

        let inner = NetStackInner {
            interface,
            device,
            sockets,
        };

        Arc::new(Self {
            inner: Mutex::new(inner),
            wg_tunnel,
            wg_tx,
        })
    }

    /// Create a new TCP socket and return its handle.
    pub fn create_tcp_socket(&self) -> SocketHandle {
        let mut inner = self.inner.lock();

        let rx_buffer = SocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let tx_buffer = SocketBuffer::new(vec![0u8; TCP_BUFFER_SIZE]);
        let socket = TcpSocket::new(rx_buffer, tx_buffer);

        inner.sockets.add(socket)
    }

    /// Connect a TCP socket to the given address.
    pub fn connect(&self, handle: SocketHandle, addr: SocketAddr) -> Result<()> {
        let mut inner = self.inner.lock();

        let local_port = 49152 + (rand::random::<u16>() % 16384);
        let local_addr = SocketAddrV4::new(self.wg_tunnel.tunnel_ip(), local_port);

        let remote = match addr {
            SocketAddr::V4(v4) => smoltcp::wire::IpEndpoint::new(
                IpAddress::v4(
                    v4.ip().octets()[0],
                    v4.ip().octets()[1],
                    v4.ip().octets()[2],
                    v4.ip().octets()[3],
                ),
                v4.port(),
            ),
            SocketAddr::V6(_) => return Err(Error::Ipv6NotSupported),
        };

        let local = smoltcp::wire::IpEndpoint::new(
            IpAddress::v4(
                local_addr.ip().octets()[0],
                local_addr.ip().octets()[1],
                local_addr.ip().octets()[2],
                local_addr.ip().octets()[3],
            ),
            local_addr.port(),
        );

        // Use destructuring to avoid split borrow issues
        let NetStackInner {
            ref mut interface,
            ref mut sockets,
            ..
        } = *inner;
        let cx = interface.context();
        let socket = sockets.get_mut::<TcpSocket>(handle);
        socket
            .connect(cx, remote, local)
            .map_err(|e| Error::TcpConnectGeneric(format!("TCP connect failed: {}", e)))?;

        log::debug!("TCP socket connecting to {} from {}", addr, local_addr);

        Ok(())
    }

    /// Check if a TCP socket is connected.
    pub fn is_connected(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.state() == TcpState::Established
    }

    /// Check if a TCP socket can send data.
    pub fn can_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.can_send()
    }

    /// Check if a TCP socket can receive data.
    pub fn can_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        let can = socket.can_recv();
        let recv_queue = socket.recv_queue();
        if recv_queue > 0 {
            log::debug!(
                "Socket can_recv={}, recv_queue={}, state={:?}",
                can,
                recv_queue,
                socket.state()
            );
        }
        can
    }

    /// Check if a TCP socket may send data (connection in progress or established).
    pub fn may_send(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.may_send()
    }

    /// Check if a TCP socket may receive data.
    pub fn may_recv(&self, handle: SocketHandle) -> bool {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.may_recv()
    }

    /// Get the TCP socket state.
    pub fn socket_state(&self, handle: SocketHandle) -> TcpState {
        let inner = self.inner.lock();
        let socket = inner.sockets.get::<TcpSocket>(handle);
        socket.state()
    }

    /// Send data on a TCP socket.
    pub fn send(&self, handle: SocketHandle, data: &[u8]) -> Result<usize> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);

        socket
            .send_slice(data)
            .map_err(|e| Error::TcpSend(e.to_string()))
    }

    /// Receive data from a TCP socket.
    pub fn recv(&self, handle: SocketHandle, buffer: &mut [u8]) -> Result<usize> {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);

        socket
            .recv_slice(buffer)
            .map_err(|e| Error::TcpRecv(e.to_string()))
    }

    /// Close a TCP socket.
    pub fn close(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock();
        let socket = inner.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
    }

    /// Remove a socket from the socket set.
    pub fn remove_socket(&self, handle: SocketHandle) {
        let mut inner = self.inner.lock();
        inner.sockets.remove(handle);
    }

    /// Poll the network stack, processing packets and updating socket states.
    /// Returns true if there was any activity.
    pub fn poll(&self) -> bool {
        let mut inner = self.inner.lock();

        let timestamp = Instant::now();

        // Destructure to allow split borrows
        let NetStackInner {
            ref mut interface,
            ref mut device,
            ref mut sockets,
        } = *inner;

        // Check if there are packets waiting
        let rx_queue_len = device.rx_queue.len();
        if rx_queue_len > 0 {
            log::trace!("NetStack poll: {} packets in rx_queue", rx_queue_len);
        }

        // Poll the interface
        let processed = interface.poll(timestamp, device, sockets);

        if processed {
            log::trace!("NetStack poll processed packets");
        }

        // Drain transmitted packets and send through WireGuard
        let tx_packets = device.drain_tx();
        let tx_count = tx_packets.len();
        drop(inner); // Release lock before async operations

        if tx_count > 0 {
            log::trace!("NetStack poll sending {} packets", tx_count);
        }

        for packet in tx_packets {
            // Log outgoing TCP packets at debug level
            if log::log_enabled!(log::Level::Debug) {
                if let Ok(ip_packet) = Ipv4Packet::new_checked(&packet) {
                    let protocol = ip_packet.next_header();
                    if protocol == smoltcp::wire::IpProtocol::Tcp {
                        if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                            let dst_port = tcp_packet.dst_port();
                            let payload_len = tcp_packet.payload().len();

                            let mut flags = String::new();
                            if tcp_packet.syn() {
                                flags.push_str("SYN ");
                            }
                            if tcp_packet.ack() {
                                flags.push_str("ACK ");
                            }
                            if tcp_packet.fin() {
                                flags.push_str("FIN ");
                            }
                            if tcp_packet.rst() {
                                flags.push_str("RST ");
                            }
                            if tcp_packet.psh() {
                                flags.push_str("PSH ");
                            }

                            log::debug!(
                                "TX: {}:{} [{}] {} bytes",
                                ip_packet.dst_addr(),
                                dst_port,
                                flags.trim(),
                                payload_len
                            );
                        }
                    }
                }
            }

            let tx = self.wg_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = tx.send(packet).await {
                    log::error!("Failed to queue packet for WireGuard: {}", e);
                }
            });
        }

        processed
    }

    /// Push a received packet (from WireGuard) into the network stack.
    pub fn push_rx_packet(&self, packet: BytesMut) {
        // Parse and log TCP packet details for debugging
        if log::log_enabled!(log::Level::Debug) {
            if let Ok(ip_packet) = Ipv4Packet::new_checked(&packet) {
                let protocol = ip_packet.next_header();
                if protocol == smoltcp::wire::IpProtocol::Tcp {
                    if let Ok(tcp_packet) = TcpPacket::new_checked(ip_packet.payload()) {
                        let src_port = tcp_packet.src_port();
                        let payload_len = tcp_packet.payload().len();

                        let mut flags = String::new();
                        if tcp_packet.syn() {
                            flags.push_str("SYN ");
                        }
                        if tcp_packet.ack() {
                            flags.push_str("ACK ");
                        }
                        if tcp_packet.fin() {
                            flags.push_str("FIN ");
                        }
                        if tcp_packet.rst() {
                            flags.push_str("RST ");
                        }
                        if tcp_packet.psh() {
                            flags.push_str("PSH ");
                        }

                        log::debug!(
                            "RX: {}:{} [{}] {} bytes",
                            ip_packet.src_addr(),
                            src_port,
                            flags.trim(),
                            payload_len
                        );
                    }
                }
            }
        }

        let mut inner = self.inner.lock();
        inner.device.push_rx(packet);
    }

    /// Run the network stack polling loop.
    pub async fn run_poll_loop(self: &Arc<Self>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(1));

        loop {
            interval.tick().await;
            self.poll();
        }
    }

    /// Run the receive loop that takes packets from WireGuard and feeds them to the stack.
    pub async fn run_rx_loop(self: &Arc<Self>, mut rx: mpsc::Receiver<BytesMut>) -> Result<()> {
        while let Some(packet) = rx.recv().await {
            log::debug!("NetStack received packet ({} bytes)", packet.len());
            self.push_rx_packet(packet);
            self.poll();
        }

        Ok(())
    }
}

/// A TCP connection through our network stack.
pub struct TcpConnection {
    /// The network stack backing this connection.
    pub netstack: Arc<NetStack>,
    /// The socket handle for this connection.
    pub handle: SocketHandle,
}

impl TcpConnection {
    /// Create a new TCP connection.
    pub async fn connect(netstack: Arc<NetStack>, addr: SocketAddr) -> Result<Self> {
        let handle = netstack.create_tcp_socket();
        netstack.connect(handle, addr)?;

        // Poll until connected or timeout
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(30);

        loop {
            netstack.poll();

            let state = netstack.socket_state(handle);
            log::trace!("TCP state: {:?}", state);

            if state == TcpState::Established {
                log::info!("TCP connection established to {}", addr);
                return Ok(Self { netstack, handle });
            }

            if state == TcpState::Closed || state == TcpState::TimeWait {
                netstack.remove_socket(handle);
                return Err(Error::TcpConnect {
                    addr,
                    message: format!("Connection failed (state: {:?})", state),
                });
            }

            if start.elapsed() > timeout {
                netstack.remove_socket(handle);
                return Err(Error::TcpTimeout);
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Read data from the connection.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();

        loop {
            self.netstack.poll();

            if self.netstack.can_recv(self.handle) {
                match self.netstack.recv(self.handle, buf) {
                    Ok(n) if n > 0 => return Ok(n),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }

            if !self.netstack.may_recv(self.handle) {
                // Connection closed
                return Ok(0);
            }

            if start.elapsed() > timeout {
                return Err(Error::ReadTimeout);
            }

            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Write data to the connection.
    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        let timeout = Duration::from_secs(30);
        let start = std::time::Instant::now();

        let mut written = 0;

        while written < data.len() {
            self.netstack.poll();

            if self.netstack.can_send(self.handle) {
                match self.netstack.send(self.handle, &data[written..]) {
                    Ok(n) => {
                        written += n;
                        log::trace!("Wrote {} bytes (total: {})", n, written);
                    }
                    Err(e) => return Err(e),
                }
            }

            if !self.netstack.may_send(self.handle) {
                // Connection closed
                return Err(Error::ConnectionClosed);
            }

            if start.elapsed() > timeout {
                return Err(Error::WriteTimeout);
            }

            if written < data.len() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        self.netstack.poll();
        Ok(written)
    }

    /// Write all data to the connection.
    pub async fn write_all(&self, data: &[u8]) -> Result<()> {
        let n = self.write(data).await?;
        if n != data.len() {
            return Err(Error::ShortWrite {
                written: n,
                expected: data.len(),
            });
        }
        Ok(())
    }

    /// Shutdown the connection.
    pub fn shutdown(&self) {
        self.netstack.close(self.handle);
    }

    /// Get the socket handle.
    pub fn handle(&self) -> SocketHandle {
        self.handle
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        self.netstack.close(self.handle);
        // Give time for FIN to be sent
        self.netstack.poll();
    }
}
