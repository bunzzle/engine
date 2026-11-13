use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use config::{Entry, Error, Table};

const MAX_COUNT: u64 = 1 << 24;

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
    })
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
    };
    table.finish()?;
    Ok(tls)
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
