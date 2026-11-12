#![allow(dead_code)]

use smtp::{Config, Event, Reply, Server, reply};

pub const LIMIT: u64 = 1 << 16;
pub const MESSAGES: u32 = 1000;
pub const TOKEN: &[u8] = b"bz_good";
pub const PLAIN: &str = "AHVzZXIAYnpfZ29vZA==";

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

pub struct Client {
    pub server: Server,
    pub output: Vec<u8>,
    pub log: Vec<String>,
    pub messages: Vec<Vec<u8>>,
    pub body: Vec<u8>,
    pub live: bool,
    pub refuse_after: Option<usize>,
    pub message: u64,
}

impl Client {
    pub fn new(implicit: bool) -> Self {
        Self::with(implicit, LIMIT)
    }

    pub fn with(implicit: bool, message: u64) -> Self {
        let mut server = Server::new(Config {
            name: "mx.example.org".into(),
            message,
            implicit,
            messages: MESSAGES,
        });
        let output = server.output();
        Self {
            server,
            output,
            log: Vec::new(),
            messages: Vec::new(),
            body: Vec::new(),
            live: false,
            refuse_after: None,
            message,
        }
    }

    pub fn ready() -> Self {
        let mut client = Self::new(true);
        client.send(b"EHLO client.example\r\n");
        client.send(format!("AUTH PLAIN {PLAIN}\r\n").as_bytes());
        client.clear();
        client
    }

    pub fn clear(&mut self) {
        self.output.clear();
        self.log.clear();
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.output).into_owned()
    }

    pub fn send(&mut self, bytes: &[u8]) -> String {
        let before = self.output.len();
        self.server.input(bytes);
        self.drive();
        String::from_utf8_lossy(&self.output[before..]).into_owned()
    }

    pub fn drive(&mut self) {
        while let Some(event) = self.server.poll() {
            self.answer(event);
        }
        self.output.extend(self.server.output());
    }

    fn answer(&mut self, event: Event) {
        match event {
            Event::Starttls => {
                self.log.push("starttls".into());
                self.output.extend(self.server.output());
                self.server.secured();
            }
            Event::Auth(secret) => {
                self.log.push("auth".into());
                if secret.expose() == TOKEN {
                    self.server.auth(Ok(()));
                } else {
                    self.server.auth(Err(reply::AUTH_FAILED));
                }
            }
            Event::Mail { from, size, body } => {
                self.log.push(format!("mail {from} {size:?} {body:?}"));
                if from.starts_with("deny") {
                    self.server
                        .mail(Err(Reply::new(550, "5.7.1", "Sender not allowed")));
                } else {
                    self.live = true;
                    self.server.mail(Ok(()));
                }
            }
            Event::Recipients(list) => {
                self.log.push(format!("rcpt {}", list.join(" ")));
                self.server.recipients(list.iter().map(|to| {
                    if to.starts_with("full") {
                        Err(reply::TOO_MANY_RECIPIENTS)
                    } else if to.starts_with("bad") {
                        Err(Reply::new(550, "5.7.1", "Recipient refused"))
                    } else {
                        Ok(())
                    }
                }));
            }
            Event::Data => {
                assert!(self.live, "data without a transaction");
                self.log.push("data".into());
                self.server.data(Ok(()));
            }
            Event::Body(bytes) => {
                assert!(self.live, "body without a transaction");
                assert_ne!(bytes, Vec::<u8>::new());
                self.body.extend_from_slice(&bytes);
                assert!(self.body.len() as u64 <= self.message);
                if self.refuse_after.is_some_and(|n| self.body.len() >= n) {
                    self.log.push("refuse".into());
                    self.server
                        .refuse(Reply::new(552, "5.3.4", "Header too big"));
                }
            }
            Event::End { lf } => {
                assert!(self.live, "end without a transaction");
                self.log.push(format!("end {lf}"));
                self.live = false;
                self.messages.push(std::mem::take(&mut self.body));
                let id = self.messages.len();
                self.server
                    .message(&Reply::owned(250, "2.0.0", format!("id{id}")));
            }
            Event::Reset => {
                self.log.push("reset".into());
                self.live = false;
                self.body.clear();
            }
            Event::Close => {
                self.log.push("close".into());
                self.live = false;
                self.body.clear();
            }
        }
    }
}
