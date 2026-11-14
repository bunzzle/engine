#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::ready;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use deliver::Dns;
use dns::{Error, Found, Lookup, Name, Type};
use rt::{Buf, TcpListener, TcpStream, now, sleep, spawn};
use tls::{Acceptor, Certs, Stream, simulated};

const CERT: &[u8] = include_bytes!("../data/a.pem");
const KEY: &str = "302e020100300506032b65700422042098cded488e5305ce6644e0188d522eac4a19a7722043c25e621026562f2dda6d";

type Answers = BTreeMap<(String, Type), Option<Found>>;

#[derive(Clone, Default)]
pub struct Zone {
    answers: Rc<RefCell<Answers>>,
    pub asked: Rc<RefCell<Vec<(String, Type)>>>,
}

impl Zone {
    pub fn set(&self, name: &str, kind: Type, found: Found) {
        self.answers
            .borrow_mut()
            .insert((name.to_owned(), kind), Some(found));
    }

    pub fn fail(&self, name: &str, kind: Type) {
        self.answers
            .borrow_mut()
            .insert((name.to_owned(), kind), None);
    }
}

impl Dns for Zone {
    fn lookup(&self, name: &Name, kind: Type) -> impl Future<Output = Result<Rc<Lookup>, Error>> {
        let key = (name.to_string(), kind);
        self.asked.borrow_mut().push(key.clone());
        let found = match self.answers.borrow().get(&key) {
            Some(Some(found)) => Ok(found.clone()),
            Some(None) => Err(Error::ServFail),
            None => Ok(Found::NxDomain),
        };
        ready(found.map(|found| {
            Rc::new(Lookup {
                name: name.clone(),
                found,
                secure: false,
                expires: now() + Duration::from_secs(3600),
            })
        }))
    }
}

#[derive(Clone)]
pub struct Script {
    pub banner: &'static str,
    pub ehlo: String,
    pub starttls: bool,
    pub inject: bool,
    pub mail: &'static str,
    pub rcpt: Rc<dyn Fn(&str) -> String>,
    pub done: &'static str,
}

impl Script {
    pub fn new(extensions: &[&str]) -> Self {
        let mut ehlo = String::from("250-mx.example.com");
        for extension in extensions {
            ehlo.push_str("\r\n250-");
            ehlo.push_str(extension);
        }
        ehlo.push_str("\r\n250 HELP");
        Self {
            banner: "220 mx.example.com ESMTP",
            ehlo,
            starttls: extensions.contains(&"STARTTLS"),
            inject: false,
            mail: "250 2.1.0 ok",
            rcpt: Rc::new(|_| "250 2.1.5 ok".to_owned()),
            done: "250 2.0.0 queued",
        }
    }
}

#[derive(Default)]
pub struct Seen {
    pub connections: u32,
    pub commands: Vec<String>,
    pub bodies: Vec<Vec<u8>>,
    pub tls: bool,
}

enum Io {
    Plain(TcpStream),
    Tls(Box<Stream>),
}

impl Io {
    async fn read(&mut self, into: &mut Vec<u8>) -> bool {
        match self {
            Self::Plain(stream) => {
                let (read, buf) = stream.read(Buf::new(4096)).await;
                into.extend_from_slice(&buf);
                matches!(read, Ok(n) if n > 0)
            }
            Self::Tls(stream) => {
                let mut buf = [0; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                into.extend_from_slice(&buf[..n]);
                n > 0
            }
        }
    }

    async fn write(&mut self, text: &str) {
        let line = format!("{text}\r\n");
        let _ = match self {
            Self::Plain(stream) => stream.write_all(Buf::from_slice(line.as_bytes())).await.0,
            Self::Tls(stream) => stream.write_all(line.as_bytes()).await,
        };
    }
}

pub fn serve(ip: IpAddr, script: Script) -> Rc<RefCell<Seen>> {
    let seen = Rc::new(RefCell::new(Seen::default()));
    let shared = Rc::clone(&seen);
    let certs = Arc::new(Certs::new(CERT, &key()).expect("certs"));
    let acceptor = Rc::new(Acceptor::new(simulated(1), certs).expect("acceptor"));
    drop(spawn(async move {
        let listener = TcpListener::bind(SocketAddr::new(ip, 25), 16)
            .await
            .expect("bind");
        while let Ok((io, _)) = listener.accept().await {
            shared.borrow_mut().connections += 1;
            drop(spawn(session(
                io,
                script.clone(),
                Rc::clone(&shared),
                Rc::clone(&acceptor),
            )));
        }
    }));
    seen
}

fn line(buf: &mut Vec<u8>) -> Option<String> {
    let at = buf.windows(2).position(|w| w == b"\r\n")?;
    let line = String::from_utf8_lossy(&buf[..at]).into_owned();
    buf.drain(..at + 2);
    Some(line)
}

async fn session(io: TcpStream, script: Script, seen: Rc<RefCell<Seen>>, acceptor: Rc<Acceptor>) {
    let mut io = Io::Plain(io);
    io.write(script.banner).await;
    if !script.banner.starts_with("220") {
        return;
    }
    let mut buf = Vec::new();
    let mut accepted = 0;
    loop {
        let Some(command) = line(&mut buf) else {
            if !io.read(&mut buf).await {
                return;
            }
            continue;
        };
        seen.borrow_mut().commands.push(command.clone());
        let upper = command.to_ascii_uppercase();
        let verb = upper.split(' ').next().unwrap_or_default();
        match verb {
            "EHLO" => io.write(&script.ehlo).await,
            "HELO" => io.write("250 mx.example.com").await,
            "STARTTLS" if script.starttls => {
                if script.inject {
                    io.write("220 2.0.0 go\r\n250 2.0.0 injected").await;
                } else {
                    io.write("220 2.0.0 go").await;
                }
                let Io::Plain(plain) = io else { return };
                let Ok(stream) = acceptor.accept(plain).await else {
                    return;
                };
                io = Io::Tls(Box::new(stream));
                seen.borrow_mut().tls = true;
                buf.clear();
            }
            "MAIL" => {
                accepted = 0;
                io.write(script.mail).await;
            }
            "RCPT" => {
                let address = command
                    .split_once('<')
                    .and_then(|(_, rest)| rest.split_once('>'))
                    .map_or("", |(address, _)| address);
                let reply = (script.rcpt)(address);
                if reply.starts_with('2') {
                    accepted += 1;
                }
                io.write(&reply).await;
            }
            "DATA" => {
                if accepted == 0 {
                    io.write("554 5.5.1 No valid recipients").await;
                    continue;
                }
                io.write("354 go").await;
                let body = loop {
                    if let Some(at) = buf.windows(5).position(|w| w == b"\r\n.\r\n") {
                        let body = buf[..at + 2].to_vec();
                        buf.drain(..at + 5);
                        break body;
                    }
                    if buf.starts_with(b".\r\n") {
                        buf.drain(..3);
                        break Vec::new();
                    }
                    if !io.read(&mut buf).await {
                        return;
                    }
                };
                seen.borrow_mut().bodies.push(body);
                if script.done.is_empty() {
                    sleep(Duration::from_secs(100_000)).await;
                    return;
                }
                io.write(script.done).await;
            }
            "RSET" => io.write("250 2.0.0 ok").await,
            "QUIT" => {
                io.write("221 2.0.0 bye").await;
                return;
            }
            _ => io.write("500 5.5.2 what").await,
        }
    }
}

fn key() -> Vec<u8> {
    let der: Vec<u8> = (0..KEY.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&KEY[i..i + 2], 16).expect("hex"))
        .collect();
    let label = "PRIVATE KEY";
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        dkim::base64::encode(&der)
    )
    .into_bytes()
}
