use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as AnyhowContext;
use bytes::{BufMut, Bytes, BytesMut};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::{Bus, Event};
use crate::virtual_iface::VirtualPort;

const MAX_PACKET: usize = 65536;
const MIN_PORT: u16 = 1000;
const MAX_PORT: u16 = 60999;
const PORT_RANGE: Range<u16> = MIN_PORT..MAX_PORT;

/// Starts the server that listens on TCP connections.
pub async fn tcp_proxy_server(
    port_forward: PortForwardConfig,
    port_pool: TcpPortPool,
    bus: Bus,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(port_forward.source)
        .await
        .context("Failed to listen on TCP proxy server")?;

    loop {
        let port_pool = port_pool.clone();
        let (socket, peer_addr) = listener
            .accept()
            .await
            .context("Failed to accept connection on TCP proxy server")?;

        // Assign a 'virtual port': this is a unique port number used to route IP packets
        // received from the WireGuard tunnel. It is the port number that the virtual client will
        // listen on.
        let virtual_port = match port_pool.next().await {
            Ok(port) => port,
            Err(e) => {
                error!(
                    "Failed to assign virtual port number for connection [{}]: {:?}",
                    peer_addr, e
                );
                continue;
            }
        };

        info!("[{}] Incoming connection from {}", virtual_port, peer_addr);

        let bus = bus.clone();
        tokio::spawn(async move {
            let port_pool = port_pool.clone();
            let result = handle_tcp_proxy_connection(socket, virtual_port, port_forward, bus).await;

            if let Err(e) = result {
                error!(
                    "[{}] Connection dropped un-gracefully: {:?}",
                    virtual_port, e
                );
            } else {
                info!("[{}] Connection closed by client", virtual_port);
            }

            tokio::time::sleep(Duration::from_millis(100)).await; // Make sure the other tasks have time to process the event
            port_pool.release(virtual_port).await;
        });
    }
}

/// Creates a virtual TCP proxy server that returns a VirtualSocket for direct async I/O operations.
/// This is different from tcp_proxy_server as it doesn't listen on a real TCP port,
/// but instead provides a virtual socket interface for direct communication.
pub async fn virtual_tcp_proxy_server(
    port_forward: PortForwardConfig,
    port_pool: TcpPortPool,
    bus: Bus,
) -> anyhow::Result<VirtualSocket> {
    info!("Creating virtual TCP proxy for {}", port_forward.source);
    VirtualSocket::new(port_forward, port_pool, bus).await
}

/// Handles a new TCP connection with its assigned virtual port.
async fn handle_tcp_proxy_connection(
    mut socket: TcpStream,
    virtual_port: VirtualPort,
    port_forward: PortForwardConfig,
    bus: Bus,
) -> anyhow::Result<()> {
    let mut endpoint = bus.new_endpoint();
    endpoint.send(Event::ClientConnectionInitiated(port_forward, virtual_port));

    let mut buffer = BytesMut::with_capacity(MAX_PACKET);
    loop {
        tokio::select! {
            readable_result = socket.readable() => {
                match readable_result {
                    Ok(_) => {
                        match socket.try_read_buf(&mut buffer) {
                            Ok(size) if size > 0 => {
                                let data = Vec::from(&buffer[..size]);
                                endpoint.send(Event::LocalData(port_forward, virtual_port, data.into()));
                                // Reset buffer
                                buffer.clear();
                            }
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Err(e) => {
                                error!(
                                    "[{}] Failed to read from client TCP socket: {:?}",
                                    virtual_port, e
                                );
                                break;
                            }
                            _ => {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("[{}] Failed to check if readable: {:?}", virtual_port, e);
                        break;
                    }
                }
            }
            event = endpoint.recv() => {
                match event {
                    Event::ClientConnectionDropped(e_vp) if e_vp == virtual_port => {
                        // This connection is supposed to be closed, stop the task.
                        break;
                    }
                    Event::RemoteData(e_vp, data) if e_vp == virtual_port => {
                        // Have remote data to send to the local client
                        if let Err(e) = socket.writable().await {
                            error!("[{}] Failed to check if writable: {:?}", virtual_port, e);
                        }
                        let expected = data.len();
                        let mut sent = 0;
                        loop {
                            if sent >= expected {
                                break;
                            }
                            match socket.write(&data[sent..expected]).await {
                                Ok(written) => {
                                    debug!("[{}] Sent {} (expected {}) bytes to local client", virtual_port, written, expected);
                                    sent += written;
                                    if sent < expected {
                                        debug!("[{}] Will try to resend remaining {} bytes to local client", virtual_port, (expected - written));
                                    }
                                },
                                Err(e) => {
                                    error!("[{}] Failed to send {} bytes to local client: {:?}", virtual_port, expected, e);
                                    break;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Notify other endpoints that this task has closed and no more data is to be sent to the local client
    endpoint.send(Event::ClientConnectionDropped(virtual_port));

    Ok(())
}

/// A pool of virtual ports available for TCP connections.
#[derive(Clone)]
pub struct TcpPortPool {
    inner: Arc<tokio::sync::RwLock<TcpPortPoolInner>>,
}

impl Default for TcpPortPool {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpPortPool {
    /// Initializes a new pool of virtual ports.
    pub fn new() -> Self {
        let mut inner = TcpPortPoolInner::default();
        let mut ports: Vec<u16> = PORT_RANGE.collect();
        ports.shuffle(&mut thread_rng());
        ports
            .into_iter()
            .for_each(|p| inner.queue.push_back(p) as ());
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(inner)),
        }
    }

    /// Requests a free port from the pool. An error is returned if none is available (exhausted max capacity).
    pub async fn next(&self) -> anyhow::Result<VirtualPort> {
        let mut inner = self.inner.write().await;
        let port = inner
            .queue
            .pop_front()
            .context("TCP virtual port pool is exhausted")?;
        Ok(VirtualPort::new(port, PortProtocol::Tcp))
    }

    /// Releases a port back into the pool.
    pub async fn release(&self, port: VirtualPort) {
        let mut inner = self.inner.write().await;
        inner.queue.push_back(port.num());
    }
}

/// Non thread-safe inner logic for TCP port pool.
#[derive(Debug, Default)]
struct TcpPortPoolInner {
    /// Remaining ports in the pool.
    queue: VecDeque<u16>,
}

/// A virtual socket that implements AsyncRead and AsyncWrite traits.
/// This allows direct interaction with the virtual port as if it were a regular socket.
pub struct VirtualSocket {
    virtual_port: VirtualPort,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<Bytes>,
    bus: Bus,
    port_forward: PortForwardConfig,
}

impl VirtualSocket {
    /// Creates a new virtual socket connection.
    pub async fn new(
        port_forward: PortForwardConfig,
        port_pool: TcpPortPool,
        bus: Bus,
    ) -> anyhow::Result<Self> {
        let virtual_port = port_pool
            .next()
            .await
            .context("Failed to get next virtual port")?;
        let (tx, rx) = mpsc::channel(100); // Buffer size of 100 messages

        let socket = Self {
            virtual_port,
            read_buffer: BytesMut::with_capacity(MAX_PACKET),
            write_buffer: BytesMut::with_capacity(MAX_PACKET),
            rx,
            tx,
            bus: bus.clone(),
            port_forward,
        };

        // Spawn a task to handle the event bus communication
        let tx = socket.tx.clone();
        let mut endpoint = bus.new_endpoint();
        endpoint.send(Event::ClientConnectionInitiated(port_forward, virtual_port));

        tokio::spawn(async move {
            loop {
                match endpoint.recv().await {
                    Event::RemoteData(vp, data) if vp == virtual_port => {
                        if tx.send(data).await.is_err() {
                            break; // Channel closed, socket was dropped
                        }
                    }
                    Event::ClientConnectionDropped(vp) if vp == virtual_port => {
                        break;
                    }
                    _ => {}
                }
            }
            endpoint.send(Event::ClientConnectionDropped(virtual_port));
        });

        Ok(socket)
    }

    /// Get the virtual port number assigned to this socket
    pub fn virtual_port(&self) -> VirtualPort {
        self.virtual_port
    }
}

impl AsyncRead for VirtualSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // First try to read from our buffer
        if !self.read_buffer.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer[..to_copy]);
            self.read_buffer.split_to(to_copy); // Use split_to instead of advance
            return Poll::Ready(Ok(()));
        }

        // Then try to get more data from the channel
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                self.read_buffer.extend_from_slice(&data);
                let to_copy = std::cmp::min(buf.remaining(), self.read_buffer.len());
                buf.put_slice(&self.read_buffer[..to_copy]);
                self.read_buffer.split_to(to_copy); // Use split_to instead of advance
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF - channel closed
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for VirtualSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut endpoint = self.bus.new_endpoint();
        endpoint.send(Event::LocalData(
            self.port_forward,
            self.virtual_port,
            buf.to_vec().into(),
        ));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // No buffering in our implementation, so flush is a no-op
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut endpoint = self.bus.new_endpoint();
        endpoint.send(Event::ClientConnectionDropped(self.virtual_port));
        Poll::Ready(Ok(()))
    }
}
