use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use control::{
    Created, Domain, KeyError, KeySource, Limits, Object, Ready, State, Tenant, Verification,
};
use crypto::{Secret, TenantKeys, Wrap};
use dns::{Name, Resolver, Type};
use node::returns::{Refused, check, disable, enable};
use rt::{Buf, JoinHandle, Runtime, UdpSocket, spawn, timeout};
use sched::{
    Answered, Attempt, Batched, Clock, Keys, Meshes, Node, Parts, Transport, Unsealable, Unwrapped,
};
use store::{DataFile, Options, SLOT_SIZE, Setup, boot};

#[path = "../../dns/tests/common/mod.rs"]
mod packets;

const DNS_AT: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 53)),
    53,
);
const DOMAIN: &str = "sender.example";
const QUERY: &str = "bounce.sender.example";
const HOST: &str = "mx.example.net";
const WAIT: Duration = Duration::from_secs(30);

fn sim(future: impl Future<Output = ()> + 'static) {
    let driver = Rc::new(rt::sim::SimDriver::new(23, rt::sim::Config::default()));
    Runtime::new(driver).block_on(async {
        timeout(WAIT, future).await.expect("test in time");
    });
}

fn resolver() -> Resolver {
    let mut settings = dns::Settings::new(vec![DNS_AT]);
    settings.tries = 1;
    Resolver::new(settings, &Secret::new([7; 32]))
}

fn host() -> Name {
    Name::parse("MX.Example.NET.").expect("host")
}

fn mx(owner: &str) -> packets::Rr {
    packets::rr(owner, Type::Mx.code(), 300, packets::mx(10, HOST))
}

fn cname(target: &str) -> packets::Rr {
    packets::rr(QUERY, 5, 300, packets::wire(target))
}

fn txt(texts: &[&[u8]]) -> Vec<packets::Rr> {
    let mut answers = vec![cname(HOST)];
    answers.extend(texts.iter().map(|text| {
        let mut data = vec![u8::try_from(text.len()).expect("short TXT")];
        data.extend_from_slice(text);
        packets::rr(HOST, Type::Txt.code(), 300, data)
    }));
    answers
}

async fn respond(socket: &UdpSocket, kind: Type, answers: &[packets::Rr]) {
    let (got, query) = socket.recv_from(Buf::new(512)).await;
    let (_, from) = got.expect("query");
    let name = Name::parse(QUERY).expect("query name");
    assert_eq!(query[2..], dns::wire::query(0, &name, kind, false)[2..]);
    let packet = packets::reply(&query, 0, answers, &[]);
    let (sent, _) = socket.send_to(Buf::from_slice(&packet), from).await;
    assert_eq!(sent.expect("reply"), packet.len());
}

async fn serve(mx: Vec<packets::Rr>, txt: Option<Vec<packets::Rr>>) -> JoinHandle<()> {
    let socket = UdpSocket::bind(DNS_AT).await.expect("bind DNS");
    spawn(async move {
        timeout(WAIT, async {
            respond(&socket, Type::Mx, &mx).await;
            if let Some(txt) = txt {
                respond(&socket, Type::Txt, &txt).await;
            }
        })
        .await
        .expect("reply in time");
    })
}

fn refused(mx: Vec<packets::Rr>, txt: Option<Vec<packets::Rr>>, reason: Refused) {
    sim(async move {
        let server = serve(mx, txt).await;
        let hosts = [host(), Name::parse(QUERY).expect("host")];
        assert_eq!(check(&resolver(), DOMAIN, &hosts).await, Err(reason));
        server.await;
    });
}

#[test]
fn direct_mx_is_refused() {
    refused(vec![mx(QUERY)], None, Refused::Cname);
}

#[test]
fn cname_to_another_host_is_refused() {
    let other = "other.example.net";
    refused(vec![cname(other), mx(other)], None, Refused::Cname);
}

#[test]
fn cname_without_mx_is_refused() {
    refused(vec![cname(HOST)], None, Refused::Mx);
}

#[test]
fn cname_with_null_mx_is_refused() {
    let null_mx = packets::rr(HOST, Type::Mx.code(), 300, packets::mx(0, "."));
    refused(vec![cname(HOST), null_mx], None, Refused::Mx);
}

#[test]
fn cname_without_spf_is_refused() {
    refused(
        vec![cname(HOST), mx(HOST)],
        Some(txt(&[b"v="])),
        Refused::Spf,
    );
}

#[test]
fn cname_with_spf10_is_refused() {
    refused(
        vec![cname(HOST), mx(HOST)],
        Some(txt(&[b"v=spf10 -all"])),
        Refused::Spf,
    );
}

#[test]
fn cname_with_two_spf_records_is_refused() {
    refused(
        vec![cname(HOST), mx(HOST)],
        Some(txt(&[b"v=spf1 -all", b"V=SpF1"])),
        Refused::Spf,
    );
}

struct Idle;

impl Transport for Idle {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }
}

struct TestKeys;

impl KeySource for TestKeys {
    fn get(&self, tenant: u32, generation: u32) -> Option<TenantKeys> {
        let root = crypto::Tenant::new(&Secret::new([7; 32]));
        Some(TenantKeys::derive(tenant, generation, &root, 1))
    }

    fn ready(&self, tenant: u32, generation: u32) -> Ready<'_> {
        Box::pin(async move { self.get(tenant, generation).ok_or(KeyError::Unknown) })
    }

    fn create(&self, _: u32, _: u32) -> Created<'_> {
        Box::pin(async { Ok(()) })
    }
}

impl Keys for TestKeys {
    fn batch(&self, _: u32, _: u32, _: u16, _: u64) -> Batched<'_> {
        Box::pin(async { Err(KeyError::Unavailable) })
    }

    fn batch_key(&self, _: u32, _: u32, _: u16, _: u64, _: Wrap) -> Unwrapped<'_> {
        Box::pin(async { Err(Unsealable::Unavailable) })
    }
}

async fn start() -> Node<Idle> {
    let options = Options {
        journal_size: 8 * SLOT_SIZE,
        region_size: 8 * SLOT_SIZE,
        region_count: 96,
        shards: 4,
    };
    let setup = Setup {
        cores: 1,
        credits: 4,
        reserve: 4,
        flush: 1,
    };
    let path = "/data/store";
    DataFile::create(path, &options)
        .await
        .expect("create store");
    let booted = boot(path, setup).await.expect("boot store");
    drop(spawn(booted.committer.run()));
    let core = booted
        .starts
        .into_iter()
        .next()
        .expect("core")
        .open()
        .await
        .expect("open core");
    let settings = sched::Settings {
        node: 3,
        spool: spool::Limits {
            recipients: 100,
            inline: 2048,
            body: 1024 * 1024,
            read: 1024 * 1024,
        },
        naming: control::Naming {
            key: *b"naming key 16 by",
            shards: options.shards,
            cache: 16,
        },
        sched: sched::Config::new(options.shards),
        budget: usize::try_from(options.region_size / 2).expect("budget"),
        watched: Vec::new(),
    };
    let parts = Parts {
        keys: Rc::new(TestKeys),
        transport: Idle,
        clock: Clock::at(rt::wall_ms(), rt::now()),
    };
    let (node, _) = Node::start(
        core,
        Meshes::new(1).take(0).expect("links"),
        settings,
        parts,
    )
    .await
    .expect("start node");
    node.write(Object::Tenant(Tenant {
        id: 1,
        generation: 1,
        state: State::Active,
        default_pool: 1,
        pools: vec![1],
        limits: Limits {
            rate: 1000,
            burst: 1000,
            connections: 10,
            queued: 1000,
        },
    }))
    .await
    .expect("write tenant");
    node
}

#[test]
fn only_verified_domains_can_enable_and_disable_needs_no_dns() {
    sim(async {
        let node = start().await;
        let unverified = node.domain_new(1, DOMAIN).await.expect("new domain");
        let id = unverified.id;
        let dns = resolver();
        assert!(matches!(
            enable(&node, &dns, &[host()], 1, id).await,
            Err(sched::Error::Control(control::Error::Invalid(
                "return path"
            )))
        ));
        assert_eq!(dns.sent(), 0);
        assert!(matches!(
            node.return_path_set(1, id, true).await,
            Err(sched::Error::Control(control::Error::Invalid(
                "return path"
            )))
        ));
        assert_eq!(node.table().domain(1, id), Some(&unverified));
        let verified = node
            .domain_write(Domain {
                state: Verification::Verified,
                ..unverified
            })
            .await
            .expect("verify");
        let server = serve(vec![cname(HOST), mx(HOST)], Some(txt(&[b"V=SpF1 -all"]))).await;
        let enabled = enable(&node, &dns, &[host()], 1, id).await.expect("enable");
        server.await;
        assert_eq!(
            enabled,
            Domain {
                return_path: true,
                ..verified.clone()
            }
        );
        assert_eq!(node.table().domain(1, id), Some(&enabled));
        assert_eq!(disable(&node, 1, id).await.expect("disable"), verified);
        assert_eq!(node.table().domain(1, id), Some(&verified));
        node.close();
    });
}
