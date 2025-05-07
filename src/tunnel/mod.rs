use std::net::IpAddr;
use std::sync::Arc;

use std::collections::VecDeque;
use std::ops::Range;
use std::time::Duration;

use anyhow::Context as AnyhowContext;
use bytes::{BufMut, Bytes, BytesMut};
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::pin::Pin;
use std::task::{Context, Poll};
use tcp::VirtualSocket;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::{PortForwardConfig, PortProtocol};
use crate::events::Bus;
use crate::tunnel::tcp::TcpPortPool;
use crate::tunnel::udp::UdpPortPool;
use crate::wg::WireGuardTunnel;

pub mod tcp;
pub mod udp;

pub async fn port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
) -> anyhow::Result<()> {
    info!(
        "Tunneling {} [{}]->[{}] (via [{}] as peer {})",
        port_forward.protocol,
        port_forward.source,
        port_forward.destination,
        &wg.endpoint,
        source_peer_ip
    );

    match port_forward.protocol {
        PortProtocol::Tcp => tcp::tcp_proxy_server(port_forward, tcp_port_pool, bus).await,
        PortProtocol::Udp => udp::udp_proxy_server(port_forward, udp_port_pool, bus).await,
    }
}

pub async fn virtual_port_forward(
    port_forward: PortForwardConfig,
    source_peer_ip: IpAddr,
    tcp_port_pool: TcpPortPool,
    udp_port_pool: UdpPortPool,
    wg: Arc<WireGuardTunnel>,
    bus: Bus,
) -> anyhow::Result<VirtualSocket> {
    info!(
        "Virtual Tunneling {} [{}]->[{}] (via [{}] as peer {})",
        port_forward.protocol,
        port_forward.source,
        port_forward.destination,
        &wg.endpoint,
        source_peer_ip
    );

    match port_forward.protocol {
        PortProtocol::Tcp => tcp::virtual_tcp_proxy_server(port_forward, tcp_port_pool, bus).await,
        PortProtocol::Udp => todo!(),
    }
}
