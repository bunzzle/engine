use http::{Event, Limits, Request, Response, Server, Status};

pub const LIMIT: u64 = 1 << 20;

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut x = self.0;
        x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        x ^ (x >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("fits")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Request {
        method: String,
        path: String,
        query: Option<String>,
        body: Vec<u8>,
    },
    Fault(Status),
}

#[derive(Debug)]
pub struct Run {
    pub seen: Vec<Seen>,
    pub output: Vec<u8>,
    pub closed: bool,
}

pub fn run(pieces: &[&[u8]]) -> Run {
    run_with(Limits::default(), pieces)
}

pub fn run_with(limits: Limits, pieces: &[&[u8]]) -> Run {
    let mut server = Server::new(limits);
    let mut seen = Vec::new();
    let mut current: Option<(Request, Vec<u8>)> = None;
    let mut output = Vec::new();
    for piece in pieces {
        server.input(piece);
        pump(&mut server, &mut seen, &mut current, &mut output);
    }
    Run {
        seen,
        output,
        closed: server.closed(),
    }
}

fn pump(
    server: &mut Server,
    seen: &mut Vec<Seen>,
    current: &mut Option<(Request, Vec<u8>)>,
    output: &mut Vec<u8>,
) {
    while let Some(event) = server.event() {
        match event {
            Event::Request(request) => match server.accept_body(LIMIT) {
                Ok(()) => *current = Some((request, Vec::new())),
                Err(status) => {
                    seen.push(Seen::Fault(status));
                    server.respond(&Response::new(status), 0);
                }
            },
            Event::Body(bytes) => current.as_mut().expect("request").1.extend(bytes),
            Event::End => {
                let (request, body) = current.take().expect("request");
                seen.push(Seen::Request {
                    method: request.method,
                    path: request.path,
                    query: request.query,
                    body,
                });
                server.respond(&Response::new(Status::OK), 0);
            }
            Event::Fault(status) => {
                *current = None;
                seen.push(Seen::Fault(status));
                server.respond(&Response::new(status), 0);
            }
        }
        output.extend(server.output());
    }
    output.extend(server.output());
}

pub fn request(method: &str, path: &str, body: &[u8]) -> Seen {
    let (path, query) = match path.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (path.to_owned(), None),
    };
    Seen::Request {
        method: method.to_owned(),
        path,
        query,
        body: body.to_vec(),
    }
}
