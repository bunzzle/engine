use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

pub(super) enum Socket {
    Listener {
        addr: SocketAddr,
        shared: bool,
        backlog: VecDeque<(u64, SocketAddr)>,
    },
    UnixListener {
        path: PathBuf,
        uid: u32,
        backlog: VecDeque<(u64, u32)>,
    },
    Stream {
        local: Option<SocketAddr>,
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
            Socket::Stream { .. } | Socket::UnixListener { .. } => false,
        })
    }

    pub(super) fn unix_at(&self, path: &Path) -> Option<u64> {
        self.sockets.iter().find_map(|(id, socket)| match socket {
            Socket::UnixListener { path: bound, .. } if bound == path => Some(*id),
            _ => None,
        })
    }

    pub(super) fn can_listen(&self, addr: SocketAddr, shared: bool) -> bool {
        self.sockets.values().all(|socket| match socket {
            Socket::Listener {
                addr: bound,
                shared: other,
                ..
            } => *bound != addr || (shared && *other),
            Socket::Udp { addr: bound, .. } => *bound != addr,
            Socket::Stream { .. } | Socket::UnixListener { .. } => true,
        })
    }

    pub(super) fn listeners_at(&self, addr: SocketAddr) -> Vec<u64> {
        self.sockets
            .iter()
            .filter_map(|(id, socket)| match socket {
                Socket::Listener { addr: bound, .. } if *bound == addr => Some(*id),
                _ => None,
            })
            .collect()
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

    fn pair(
        &mut self,
        client_addr: Option<SocketAddr>,
        server_addr: Option<SocketAddr>,
    ) -> (u64, u64) {
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
            local: server_addr,
            peer: client,
            inbound: VecDeque::new(),
            eof: false,
            reset: false,
        });
        (client, server)
    }

    pub(super) fn connect(&mut self, listener: u64, addr: SocketAddr) -> u64 {
        let client_addr = self.bind_addr(SocketAddr::new(addr.ip(), 0));
        let (client, server) = self.pair(Some(client_addr), Some(addr));
        if let Some(Socket::Listener { backlog, .. }) = self.sockets.get_mut(&listener) {
            backlog.push_back((server, client_addr));
        }
        client
    }

    pub(super) fn connect_unix(&mut self, listener: u64, uid: u32) -> Option<(u64, u32)> {
        let Some(Socket::UnixListener {
            uid: server_uid, ..
        }) = self.sockets.get(&listener)
        else {
            return None;
        };
        let server_uid = *server_uid;
        let (client, server) = self.pair(None, None);
        if let Some(Socket::UnixListener { backlog, .. }) = self.sockets.get_mut(&listener) {
            backlog.push_back((server, uid));
        }
        Some((client, server_uid))
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
