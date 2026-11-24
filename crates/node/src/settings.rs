use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use config::{Entry, Error, Table};

const MAX_COUNT: u64 = 1 << 24;
const MAX_DEADLINE: Duration = Duration::from_secs(540);

#[derive(Clone, Debug)]
pub struct Config {
    pub id: u32,
    pub cores: u16,
    pub boot: Duration,
    pub store: Store,
    pub keys: Keys,
    pub tls: Tls,
    pub session: intake::Config,
    pub limits: intake::Limits,
    pub listen: Vec<Listen>,
    pub api: Option<Api>,
    pub metrics: Option<Metrics>,
    pub dns: dns::Settings,
    pub delivery: Delivery,
    pub tlsrpt: Option<Tlsrpt>,
    pub webhooks: deliver::HookSettings,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlsrpt {
    pub tenant: u32,
    pub from: String,
}

#[derive(Clone, Debug)]
pub struct Api {
    pub settings: api::Config,
    pub listen: Vec<SocketAddr>,
    pub plain: Vec<SocketAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metrics {
    pub listen: Vec<SocketAddr>,
    pub interval: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub settings: deliver::Settings,
    pub connections: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    pub path: PathBuf,
    pub credits: u32,
    pub reserve: u32,
    pub flush: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    pub socket: PathBuf,
    pub server: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tls {
    pub chain: PathBuf,
    pub key: PathBuf,
    pub roots: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Listen {
    pub address: SocketAddr,
    pub implicit: bool,
}

pub fn parse(text: &str) -> Result<Config, Error> {
    let mut root = config::parse(text)?;
    let mut node = section(&mut root, "node")?;
    let id = int(&node.require("id")?, 0, u32::MAX.into())?;
    let name = node.require("name")?;
    if !intake::node_name(name.str()?) {
        return Err(name.error("must be a host name"));
    }
    let cores =
        thread::available_parallelism().map_or(1, |n| u16::try_from(n.get()).unwrap_or(u16::MAX));
    let cores = number(&mut node, "cores", 1, u16::MAX.into(), cores)?;
    let boot = duration(&mut node, "boot_deadline", Duration::from_secs(60))?;
    node.finish()?;
    let store = store(section(&mut root, "store")?)?;
    let keys = keys(section(&mut root, "keys")?)?;
    let tls = tls(section(&mut root, "tls")?)?;
    let mut session = intake::Config::new(name.str()?.to_owned());
    if let Some(table) = root.table("intake") {
        intake(table, &mut session)?;
    }
    let mut limits = intake::Limits::default();
    if let Some(table) = root.table("guard") {
        guard(table, &mut limits)?;
    }
    let listen = listen(root.tables("listen"))?;
    let api = match root.table("api") {
        Some(table) => Some(http(table, name.str()?, session.lifetime, &listen)?),
        None => None,
    };
    let metrics = match root.table("metrics") {
        Some(table) => Some(metrics(table, &listen, api.as_ref())?),
        None => None,
    };
    let dns = dns(section(&mut root, "dns")?)?;
    let mut delivery = Delivery {
        settings: deliver::Settings::new(name.str()?),
        connections: 10,
    };
    if let Some(table) = root.table("deliver") {
        deliver(table, &mut delivery, tls.roots.is_some())?;
    }
    let tlsrpt = match root.table("tlsrpt") {
        Some(table) => tlsrpt(table, &mut delivery.settings, tls.roots.is_some())?,
        None => None,
    };
    let webhooks = match root.table("webhooks") {
        Some(table) => webhooks(table, tls.roots.is_some())?,
        None => deliver::HookSettings::default(),
    };
    root.finish()?;
    Ok(Config {
        id,
        cores,
        boot,
        store,
        keys,
        tls,
        session,
        limits,
        listen,
        api,
        metrics,
        dns,
        delivery,
        tlsrpt,
        webhooks,
    })
}

fn webhooks(mut table: Table, roots: bool) -> Result<deliver::HookSettings, Error> {
    if !roots {
        return Err(Error::at(
            table.line(),
            1,
            "[webhooks] needs `roots` in [tls]",
        ));
    }
    let mut settings = deliver::HookSettings::default();
    if let Some(entry) = table.take("egress") {
        let ip = entry
            .str()?
            .parse::<IpAddr>()
            .map_err(|_| entry.error("must be an IP address"))?;
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(entry.error("must be a unicast address"));
        }
        settings.egress = Some(ip);
    }
    allow(&mut table, &mut settings.allow)?;
    nat64(&mut table, &mut settings.nat64)?;
    table.finish()?;
    Ok(settings)
}

fn allow(table: &mut Table, allow: &mut Vec<deliver::Cidr>) -> Result<(), Error> {
    if let Some(entry) = table.take("allow") {
        for text in entry.strs()? {
            let cidr = deliver::Cidr::parse(text)
                .ok_or_else(|| entry.error(format!("`{text}` must be an address or CIDR")))?;
            allow.push(cidr);
        }
    }
    Ok(())
}

fn nat64(table: &mut Table, nat64: &mut Vec<deliver::Cidr>) -> Result<(), Error> {
    if let Some(entry) = table.take("nat64") {
        for text in entry.strs()? {
            let cidr = deliver::Cidr::nat64(text).ok_or_else(|| {
                entry.error(format!(
                    "`{text}` must be an IPv6 prefix of length 32, 40, 48, 56, 64 or 96"
                ))
            })?;
            nat64.push(cidr);
        }
    }
    Ok(())
}

fn tlsrpt(
    mut table: Table,
    settings: &mut deliver::Settings,
    roots: bool,
) -> Result<Option<Tlsrpt>, Error> {
    let on = match table.take("on") {
        Some(entry) => {
            let on = entry.bool()?;
            if on && !roots {
                return Err(entry.error("needs `roots` in [tls]"));
            }
            on
        }
        None => false,
    };
    if !on {
        table.finish()?;
        return Ok(None);
    }
    let tenant = int(&table.require("tenant")?, 1, u32::MAX.into())?;
    let from = table.require("from")?;
    let submitter = match from.str()?.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && intake::node_name(domain) => {
            domain.to_ascii_lowercase()
        }
        _ => return Err(from.error("must be an address")),
    };
    let mut text = |key: &str| -> Result<String, Error> {
        let entry = table.require(key)?;
        let value = entry.str()?;
        if value.is_empty() {
            return Err(entry.error("must not be empty"));
        }
        Ok(value.to_owned())
    };
    let organization = text("organization")?;
    let contact = text("contact")?;
    table.finish()?;
    settings.tlsrpt = true;
    settings.report_tenant = Some(tenant);
    settings.reporter = deliver::Reporter {
        from: from.str()?.to_owned(),
        organization,
        contact,
        submitter,
    };
    Ok(Some(Tlsrpt {
        tenant,
        from: from.str()?.to_owned(),
    }))
}

fn store(mut table: Table) -> Result<Store, Error> {
    let store = Store {
        path: path(&table.require("path")?)?,
        credits: number(&mut table, "credits", 1, 1024, 4)?,
        reserve: number(&mut table, "reserve", 0, 1024, 4)?,
        flush: number(&mut table, "flush", 0, 1024, 1)?,
    };
    table.finish()?;
    Ok(store)
}

fn keys(mut table: Table) -> Result<Keys, Error> {
    let euid = sys::process::euid();
    let keys = Keys {
        socket: path(&table.require("socket")?)?,
        server: number(&mut table, "server", 0, u32::MAX.into(), euid)?,
    };
    table.finish()?;
    Ok(keys)
}

fn tls(mut table: Table) -> Result<Tls, Error> {
    let tls = Tls {
        chain: path(&table.require("chain")?)?,
        key: path(&table.require("key")?)?,
        roots: table.take("roots").map(|entry| path(&entry)).transpose()?,
    };
    table.finish()?;
    Ok(tls)
}

fn dns(mut table: Table) -> Result<dns::Settings, Error> {
    let entry = table.require("servers")?;
    let mut servers: Vec<SocketAddr> = Vec::new();
    for text in entry.strs()? {
        let server = text
            .parse()
            .or_else(|_| text.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
            .map_err(|_| {
                entry.error("must list addresses such as \"127.0.0.1\" or \"[::1]:53\"")
            })?;
        if !servers.contains(&server) {
            servers.push(server);
        }
    }
    if servers.is_empty() {
        return Err(entry.error("must list at least one server"));
    }
    let mut settings = dns::Settings::new(servers);
    if let Some(entry) = table.take("dnssec") {
        settings.dnssec = entry.bool()?;
        if settings.dnssec && !settings.servers.iter().all(|s| s.ip().is_loopback()) {
            return Err(entry.error("needs every server on loopback"));
        }
    }
    settings.timeout = duration(&mut table, "timeout", settings.timeout)?;
    settings.tries = number(&mut table, "tries", 1, 10, settings.tries)?;
    settings.cache = number(&mut table, "cache", 0, MAX_COUNT, settings.cache)?;
    table.finish()?;
    Ok(settings)
}

fn deliver(mut table: Table, delivery: &mut Delivery, roots: bool) -> Result<(), Error> {
    let settings = &mut delivery.settings;
    if let Some(entry) = table.take("ehlo") {
        let name = entry.str()?;
        if !intake::node_name(name) {
            return Err(entry.error("must be a host name"));
        }
        name.clone_into(&mut settings.ehlo);
    }
    delivery.connections = number(&mut table, "connections", 1, 100_000, delivery.connections)?;
    if let Some(entry) = table.take("deadline") {
        let value = entry.duration()?;
        if value.is_zero() || value > MAX_DEADLINE {
            return Err(entry.error("must be more than zero and at most 9m"));
        }
        settings.deadline = value;
    }
    settings.wait = duration(&mut table, "wait", settings.wait)?;
    settings.idle = duration(&mut table, "idle", settings.idle)?;
    settings.reuse = number(&mut table, "reuse", 1, 1_000_000, settings.reuse)?;
    settings.pooled = number(&mut table, "pooled", 0, 1_000_000, settings.pooled)?;
    settings.dead = duration(&mut table, "dead", settings.dead)?;
    if let Some(entry) = table.take("mta_sts") {
        settings.mta_sts = entry.bool()?;
        if settings.mta_sts && !roots {
            return Err(entry.error("needs `roots` in [tls]"));
        }
    }
    if let Some(entry) = table.take("egress") {
        let ip = entry
            .str()?
            .parse::<IpAddr>()
            .map_err(|_| entry.error("must be an IP address"))?;
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(entry.error("must be a unicast address"));
        }
        settings.egress = Some(ip);
    }
    if let Some(entry) = table.take("eight_bit") {
        settings.eight_bit = match entry.str()? {
            "send" => deliver::EightBit::Send,
            "fail" => deliver::EightBit::Fail,
            _ => return Err(entry.error("must be \"send\" or \"fail\"")),
        };
    }
    allow(&mut table, &mut settings.allow)?;
    nat64(&mut table, &mut settings.nat64)?;
    let t = &mut settings.timeouts;
    t.connect = duration(&mut table, "connect_timeout", t.connect)?;
    t.banner = duration(&mut table, "banner_timeout", t.banner)?;
    t.ehlo = duration(&mut table, "ehlo_timeout", t.ehlo)?;
    t.starttls = duration(&mut table, "starttls_timeout", t.starttls)?;
    t.rset = duration(&mut table, "rset_timeout", t.rset)?;
    t.command = duration(&mut table, "command_timeout", t.command)?;
    t.body = duration(&mut table, "body_timeout", t.body)?;
    t.final_reply = duration(&mut table, "final_timeout", t.final_reply)?;
    table.finish()
}

fn intake(mut table: Table, session: &mut intake::Config) -> Result<(), Error> {
    let lifetime = Duration::from_millis(session.lifetime);
    let lifetime = duration(&mut table, "lifetime", lifetime)?;
    session.lifetime = u64::try_from(lifetime.as_millis()).unwrap_or(u64::MAX);
    session.messages = number(&mut table, "messages", 1, 1_000_000, session.messages)?;
    session.handshake = duration(&mut table, "handshake", session.handshake)?;
    session.auth = duration(&mut table, "auth", session.auth)?;
    session.idle = duration(&mut table, "idle", session.idle)?;
    session.data = duration(&mut table, "data", session.data)?;
    session.session = duration(&mut table, "session", session.session)?;
    session.drain = duration(&mut table, "drain", session.drain)?;
    table.finish()
}

fn guard(mut table: Table, limits: &mut intake::Limits) -> Result<(), Error> {
    let failures = 1_000_000;
    limits.sessions = number(&mut table, "sessions", 1, MAX_COUNT, limits.sessions)?;
    limits.per_net = number(&mut table, "per_net", 1, u16::MAX.into(), limits.per_net)?;
    limits.net_failures = number(&mut table, "net_failures", 1, failures, limits.net_failures)?;
    limits.wide_failures = number(
        &mut table,
        "wide_failures",
        1,
        failures,
        limits.wide_failures,
    )?;
    limits.ban = duration(&mut table, "ban", limits.ban)?;
    limits.leak = duration(&mut table, "leak", limits.leak)?;
    limits.entries = number(&mut table, "entries", 1, MAX_COUNT, limits.entries)?;
    limits.budget = size(&mut table, "budget", 1 << 20, 1 << 40, limits.budget)?;
    limits.ask = duration(&mut table, "ask", limits.ask)?;
    table.finish()
}

fn listen(tables: Vec<Table>) -> Result<Vec<Listen>, Error> {
    if tables.is_empty() {
        return Err(Error::at(1, 1, "missing [[listen]]"));
    }
    let mut listen: Vec<Listen> = Vec::with_capacity(tables.len());
    for mut table in tables {
        let entry = table.require("address")?;
        let address = entry
            .str()?
            .parse()
            .map_err(|_| entry.error("must be an address such as \"0.0.0.0:25\" or \"[::]:25\""))?;
        if listen.iter().any(|l| l.address == address) {
            return Err(entry.error("is listed twice"));
        }
        let implicit = match table.take("mode") {
            None => false,
            Some(mode) => match mode.str()? {
                "starttls" => false,
                "implicit" => true,
                _ => return Err(mode.error("must be \"starttls\" or \"implicit\"")),
            },
        };
        table.finish()?;
        listen.push(Listen { address, implicit });
    }
    Ok(listen)
}

fn http(mut table: Table, name: &str, lifetime: u64, smtp: &[Listen]) -> Result<Api, Error> {
    let mut settings = api::Config::new(name.to_owned());
    settings.lifetime = lifetime;
    let mut taken: Vec<SocketAddr> = smtp.iter().map(|l| l.address).collect();
    let listen = addresses(&mut table, "listen", &mut taken, false)?;
    let plain = addresses(&mut table, "plain", &mut taken, true)?;
    if listen.is_empty() && plain.is_empty() {
        return Err(Error::at(1, 1, "[api] needs `listen` or `plain`"));
    }
    if let Some(entry) = table.take("max_body") {
        let value = entry.size()?;
        if !(1024..=1 << 34).contains(&value) {
            return Err(entry.error("must be between 1024 and 17179869184 bytes"));
        }
        settings.max_body = Some(value);
    }
    let limits = &mut settings.limits;
    limits.requests = number(&mut table, "requests", 1, 1_000_000, limits.requests)?;
    let t = &mut settings.timeouts;
    t.handshake = duration(&mut table, "handshake", t.handshake)?;
    t.head = duration(&mut table, "head", t.head)?;
    t.body = duration(&mut table, "body", t.body)?;
    t.idle = duration(&mut table, "idle", t.idle)?;
    settings.drain = duration(&mut table, "drain", settings.drain)?;
    table.finish()?;
    Ok(Api {
        settings,
        listen,
        plain,
    })
}

fn metrics(mut table: Table, smtp: &[Listen], api: Option<&Api>) -> Result<Metrics, Error> {
    let mut taken: Vec<SocketAddr> = smtp.iter().map(|l| l.address).collect();
    if let Some(api) = api {
        taken.extend(api.listen.iter().chain(&api.plain));
    }
    let listen = addresses(&mut table, "listen", &mut taken, false)?;
    if listen.is_empty() {
        return Err(Error::at(1, 1, "[metrics] needs `listen`"));
    }
    let interval = match table.take("interval") {
        Some(entry) => {
            let value = entry.duration()?;
            if !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&value) {
                return Err(entry.error("must be between 1s and 60s"));
            }
            value
        }
        None => Duration::from_secs(1),
    };
    table.finish()?;
    Ok(Metrics { listen, interval })
}

fn addresses(
    table: &mut Table,
    key: &str,
    taken: &mut Vec<SocketAddr>,
    loopback: bool,
) -> Result<Vec<SocketAddr>, Error> {
    let Some(entry) = table.take(key) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for text in entry.strs()? {
        let address: SocketAddr = text
            .parse()
            .map_err(|_| entry.error("must list addresses such as \"0.0.0.0:443\""))?;
        if taken.contains(&address) {
            return Err(entry.error("lists an address twice"));
        }
        if loopback && !address.ip().is_loopback() {
            return Err(entry.error("must list loopback addresses only"));
        }
        taken.push(address);
        out.push(address);
    }
    Ok(out)
}

fn section(root: &mut Table, name: &str) -> Result<Table, Error> {
    root.table(name)
        .ok_or_else(|| Error::at(1, 1, format!("missing [{name}]")))
}

fn int<N: TryFrom<u64>>(entry: &Entry, min: u64, max: u64) -> Result<N, Error> {
    let value = entry.number(min, max)?;
    N::try_from(value).map_err(|_| entry.error("is out of range"))
}

fn number<N: TryFrom<u64>>(
    table: &mut Table,
    key: &str,
    min: u64,
    max: u64,
    default: N,
) -> Result<N, Error> {
    match table.take(key) {
        Some(entry) => int(&entry, min, max),
        None => Ok(default),
    }
}

fn duration(table: &mut Table, key: &str, default: Duration) -> Result<Duration, Error> {
    let Some(entry) = table.take(key) else {
        return Ok(default);
    };
    let value = entry.duration()?;
    if value.is_zero() {
        return Err(entry.error("must be more than zero"));
    }
    Ok(value)
}

fn size(table: &mut Table, key: &str, min: u64, max: u64, default: usize) -> Result<usize, Error> {
    let Some(entry) = table.take(key) else {
        return Ok(default);
    };
    let value = entry.size()?;
    if !(min..=max).contains(&value) {
        return Err(entry.error(format!("must be between {min} and {max} bytes")));
    }
    usize::try_from(value).map_err(|_| entry.error("is out of range"))
}

fn path(entry: &Entry) -> Result<PathBuf, Error> {
    let text = entry.str()?;
    if !text.starts_with('/') {
        return Err(entry.error("must be an absolute path"));
    }
    Ok(PathBuf::from(text))
}
