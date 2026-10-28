use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

pub(super) enum Socket {
    Listener {
        addr: SocketAddr,
        backlog: VecDeque<(u64, SocketAddr)>,
    },
    Stream {
        local: SocketAddr,
        peer: u64,
        inbound: VecDeque<u8>,
        eof: bool,
        reset: bool,
    },
    Udp {
        addr: SocketAddr,
        inbound: VecDeque<(Vec<u8>, SocketAddr)>,
    },
}

pub(super) enum Delivery {
    Bytes {
        to: u64,
        data: Vec<u8>,
    },
    Eof {
        to: u64,
    },
    Datagram {
        to: SocketAddr,
        from: SocketAddr,
        data: Vec<u8>,
    },
}

#[derive(Default)]
pub(super) struct Net {
    pub(super) sockets: BTreeMap<u64, Socket>,
    next_id: u64,
    next_port: u16,
    unreachable: BTreeSet<IpAddr>,
}

impl Net {
    pub(super) fn add(&mut self, socket: Socket) -> u64 {
        self.next_id += 1;
        self.sockets.insert(self.next_id, socket);
        self.next_id
    }

    pub(super) fn bind_addr(&mut self, mut addr: SocketAddr) -> SocketAddr {
        if addr.port() == 0 {
            self.next_port = self.next_port.max(40_000) + 1;
            addr.set_port(self.next_port);
        }
        addr
    }

    pub(super) fn in_use(&self, addr: SocketAddr) -> bool {
        self.sockets.values().any(|socket| match socket {
            Socket::Listener { addr: bound, .. } | Socket::Udp { addr: bound, .. } => {
                *bound == addr
            }
            Socket::Stream { .. } => false,
        })
    }

    pub(super) fn listener_at(&self, addr: SocketAddr) -> Option<u64> {
        self.sockets.iter().find_map(|(id, socket)| match socket {
            Socket::Listener { addr: bound, .. } if *bound == addr => Some(*id),
            _ => None,
        })
    }

    pub(super) fn udp_at(&self, addr: SocketAddr) -> Option<u64> {
        self.sockets.iter().find_map(|(id, socket)| match socket {
            Socket::Udp { addr: bound, .. } if *bound == addr => Some(*id),
            _ => None,
        })
    }

    pub(super) fn reachable(&self, addr: SocketAddr) -> bool {
        !self.unreachable.contains(&addr.ip())
    }

    pub(super) fn set_reachable(&mut self, ip: IpAddr, reachable: bool) {
        if reachable {
            self.unreachable.remove(&ip);
        } else {
            self.unreachable.insert(ip);
        }
    }

    pub(super) fn connect(&mut self, listener: u64, addr: SocketAddr) -> u64 {
        let client_addr = self.bind_addr(SocketAddr::new(addr.ip(), 0));
        let client = self.next_id + 1;
        let server = self.next_id + 2;
        self.add(Socket::Stream {
            local: client_addr,
            peer: server,
            inbound: VecDeque::new(),
            eof: false,
            reset: false,
        });
        self.add(Socket::Stream {
            local: addr,
            peer: client,
            inbound: VecDeque::new(),
            eof: false,
            reset: false,
        });
        if let Some(Socket::Listener { backlog, .. }) = self.sockets.get_mut(&listener) {
            backlog.push_back((server, client_addr));
        }
        client
    }

    pub(super) fn reset(&mut self, id: u64) {
        let peer = match self.sockets.get_mut(&id) {
            Some(Socket::Stream { reset, peer, .. }) => {
                *reset = true;
                Some(*peer)
            }
            _ => None,
        };
        if let Some(Socket::Stream { reset, .. }) = peer.and_then(|p| self.sockets.get_mut(&p)) {
            *reset = true;
        }
    }

    pub(super) fn deliver(&mut self, delivery: Delivery) {
        match delivery {
            Delivery::Bytes { to, data } => {
                if let Some(Socket::Stream { inbound, .. }) = self.sockets.get_mut(&to) {
                    inbound.extend(data);
                }
            }
            Delivery::Eof { to } => {
                if let Some(Socket::Stream { eof, .. }) = self.sockets.get_mut(&to) {
                    *eof = true;
                }
            }
            Delivery::Datagram { to, from, data } => {
                if let Some(id) = self.udp_at(to)
                    && let Some(Socket::Udp { inbound, .. }) = self.sockets.get_mut(&id)
                {
                    inbound.push_back((data, from));
                }
            }
        }
    }
}
