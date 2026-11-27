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
    pub mx: intake::Limits,
    pub listen: Vec<Listen>,
    pub api: Option<Api>,
    pub metrics: Option<Metrics>,
    pub admin: Option<Admin>,
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
    pub tenants: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admin {
    pub socket: PathBuf,
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
    pub mx: bool,
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
    let mut mx = intake::Limits::default();
    if let Some(table) = root.table("mx") {
        guard(table, &mut mx)?;
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
    let admin = match root.table("admin") {
        Some(table) => Some(admin(table, &keys)?),
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
        mx,
        listen,
        api,
        metrics,
        admin,
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

fn admin(mut table: Table, keys: &Keys) -> Result<Admin, Error> {
    let entry = table.require("socket")?;
    let socket = path(&entry)?;
    if socket == keys.socket {
        return Err(entry.error("must differ from the keys socket"));
    }
    table.finish()?;
    Ok(Admin { socket })
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
    sites(&mut table, &mut settings.sites)?;
    warmups(&mut table, &mut settings.warmups)?;
    table.finish()
}

fn sites(table: &mut Table, sites: &mut Vec<deliver::Site>) -> Result<(), Error> {
    for mut rule in table.tables("site") {
        let name = rule.require("name")?;
        let text = name.str()?;
        if text.is_empty() || text.len() > 255 {
            return Err(name.error("must be between 1 and 255 bytes"));
        }
        if !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(name.error("must hold only letters, digits and `-`"));
        }
        if sites.iter().any(|site| site.name == text) {
            return Err(name.error("is listed twice"));
        }
        let suffix = rule.require("suffix")?;
        let mut suffixes = Vec::new();
        for host in suffix.strs()? {
            let host = host.to_ascii_lowercase();
            if !intake::node_name(&host) {
                return Err(suffix.error("must list host names"));
            }
            suffixes.push(host);
        }
        if suffixes.is_empty() {
            return Err(suffix.error("must list at least one host name"));
        }
        let mut site = deliver::Site::new(text.to_owned(), suffixes);
        site.rate = optional(&mut rule, "rate", 1, 1_000_000_000)?;
        if let Some(entry) = rule.take("burst") {
            if site.rate.is_none() {
                return Err(entry.error("needs `rate`"));
            }
            site.burst = int(&entry, 1, 1_000_000)?;
        }
        site.connect_rate = optional(&mut rule, "connect_rate", 1, 1_000_000)?;
        site.reuse = optional(&mut rule, "reuse", 1, 1_000_000)?;
        rule.finish()?;
        sites.push(site);
    }
    Ok(())
}

fn warmups(table: &mut Table, warmups: &mut Vec<deliver::Warmup>) -> Result<(), Error> {
    for mut rule in table.tables("warmup") {
        let entry = rule.require("egress")?;
        let egress = entry
            .str()?
            .parse::<IpAddr>()
            .map_err(|_| entry.error("must be an IP address"))?;
        if egress.is_unspecified() || egress.is_multicast() {
            return Err(entry.error("must be a unicast address"));
        }
        if warmups.iter().any(|warmup| warmup.egress == egress) {
            return Err(entry.error("is listed twice"));
        }
        let from = rule.require("from")?;
        let day = unix_day(&from)?;
        let caps = match rule.take("caps") {
            Some(entry) => caps(&entry)?,
            None => deliver::default_caps(),
        };
        rule.finish()?;
        warmups.push(deliver::Warmup {
            egress,
            from: day,
            caps,
        });
    }
    Ok(())
}

fn unix_day(entry: &Entry) -> Result<u64, Error> {
    let text = entry.str()?;
    let date = || entry.error("must be a date like 2026-01-31");
    let Some((year, rest)) = text.split_once('-') else {
        return Err(date());
    };
    let Some((month, day)) = rest.split_once('-') else {
        return Err(date());
    };
    if year.len() != 4
        || month.len() != 2
        || day.len() != 2
        || !text.bytes().all(|b| b == b'-' || b.is_ascii_digit())
    {
        return Err(date());
    }
    let year: i64 = year.parse().map_err(|_| date())?;
    let month: i64 = month.parse().map_err(|_| date())?;
    let day: i64 = day.parse().map_err(|_| date())?;
    if year < 1970 || !(1..=12).contains(&month) {
        return Err(date());
    }
    let leaps = u64::try_from(year).map_err(|_| date())?;
    let leap = leaps.is_multiple_of(4) && (!leaps.is_multiple_of(100) || leaps.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let last = days[usize::try_from(month - 1).map_err(|_| date())?];
    if day < 1 || day > last {
        return Err(date());
    }
    u64::try_from(days_from_civil(year, month, day)).map_err(|_| date())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn caps(entry: &Entry) -> Result<Vec<u32>, Error> {
    let config::Value::Array(items) = entry.value() else {
        return Err(entry.error("must list 1 to 365 daily caps"));
    };
    if items.is_empty() || items.len() > 365 {
        return Err(entry.error("must list 1 to 365 daily caps"));
    }
    let mut caps = Vec::with_capacity(items.len());
    for item in items {
        let config::Value::Int(number) = item else {
            return Err(entry.error("must be between 1 and 1000000000"));
        };
        let cap = u32::try_from(*number)
            .ok()
            .filter(|cap| (1..=1_000_000_000).contains(cap))
            .ok_or_else(|| entry.error("must be between 1 and 1000000000"))?;
        caps.push(cap);
    }
    Ok(caps)
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
        let mx = match table.take("mx") {
            Some(entry) => entry.bool()?,
            None => false,
        };
        table.finish()?;
        listen.push(Listen {
            address,
            implicit,
            mx,
        });
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
    let tenants = match table.take("tenants") {
        Some(entry) => tenants(&entry, &listen)?,
        None => Vec::new(),
    };
    table.finish()?;
    Ok(Metrics {
        listen,
        interval,
        tenants,
    })
}

const METRIC_TENANTS: usize = 64;

fn tenants(entry: &Entry, listen: &[SocketAddr]) -> Result<Vec<u32>, Error> {
    let expected = || entry.error("must be an array of tenant ids");
    let config::Value::Array(items) = entry.value() else {
        return Err(expected());
    };
    if !items.is_empty() && !listen.iter().all(|a| private(a.ip())) {
        return Err(
            entry.error("needs every metrics `listen` address on loopback or a private network")
        );
    }
    if items.len() > METRIC_TENANTS {
        return Err(entry.error(format!("lists more than {METRIC_TENANTS} tenants")));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let config::Value::Int(number) = item else {
            return Err(expected());
        };
        let id = u32::try_from(*number)
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| entry.error(format!("must list ids between 1 and {}", u32::MAX)))?;
        if out.contains(&id) {
            return Err(entry.error("lists a tenant twice"));
        }
        out.push(id);
    }
    Ok(out)
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

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    }
}

fn int<N: TryFrom<u64>>(entry: &Entry, min: u64, max: u64) -> Result<N, Error> {
    let value = entry.number(min, max)?;
    N::try_from(value).map_err(|_| entry.error("is out of range"))
}

fn optional<N: TryFrom<u64>>(
    table: &mut Table,
    key: &str,
    min: u64,
    max: u64,
) -> Result<Option<N>, Error> {
    table
        .take(key)
        .map(|entry| int(&entry, min, max))
        .transpose()
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
