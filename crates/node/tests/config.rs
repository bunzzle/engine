use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use node::{Listen, check, key_file, parse};

const CHAIN: &[u8] = include_bytes!("data/a.pem");
const KEY: &[u8] = include_bytes!("data/a.key");

const MINIMAL: &str = r#"
[node]
id = 7
name = "mx.example.org"

[store]
path = "/var/lib/bunzzle"

[keys]
socket = "/run/bunzzle/keys.sock"

[tls]
chain = "/etc/bunzzle/chain.pem"
key = "/etc/bunzzle/key.pem"

[[listen]]
address = "0.0.0.0:25"
"#;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("node-config-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn write(path: &Path, data: &[u8], mode: u32) {
    let _ = fs::remove_file(path);
    fs::write(path, data).expect("write");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

fn error(text: &str) -> String {
    parse(text).expect_err("refused").to_string()
}

#[test]
fn minimal_config_takes_defaults() {
    let config = parse(MINIMAL).expect("config");
    assert_eq!(config.id, 7);
    assert!(config.cores >= 1);
    assert_eq!(config.boot, Duration::from_secs(60));
    assert_eq!(config.store.path, Path::new("/var/lib/bunzzle"));
    assert_eq!(
        (
            config.store.credits,
            config.store.reserve,
            config.store.flush
        ),
        (4, 4, 1)
    );
    assert_eq!(config.keys.server, sys::process::euid());
    assert_eq!(config.session.name, "mx.example.org");
    assert_eq!(config.session.drain, Duration::from_secs(30));
    assert_eq!(config.limits, intake::Limits::default());
    assert_eq!(
        config.listen,
        [Listen {
            address: "0.0.0.0:25".parse().expect("address"),
            implicit: false,
        }]
    );
}

#[test]
fn every_setting_is_read() {
    let text = format!(
        r#"{MINIMAL}
[[listen]]
address = "[::]:465"
mode = "implicit"

[intake]
lifetime = "2h"
messages = 50
handshake = "5s"
auth = "20s"
idle = "1m"
data = "2m"
session = "30m"
drain = "10s"

[guard]
sessions = 200
per_net = 4
net_failures = 3
wide_failures = 9
ban = "1h"
leak = "30s"
entries = 1_000
budget = "16MiB"
ask = "2s"
"#
    )
    .replace("id = 7", "id = 7\ncores = 3\nboot_deadline = \"90s\"")
    .replace("[keys]", "[keys]\nserver = 501")
    .replace("[store]", "[store]\ncredits = 8\nreserve = 0\nflush = 2");
    let config = parse(&text).expect("config");
    assert_eq!((config.cores, config.boot), (3, Duration::from_secs(90)));
    assert_eq!(
        (
            config.store.credits,
            config.store.reserve,
            config.store.flush
        ),
        (8, 0, 2)
    );
    assert_eq!(config.keys.server, 501);
    let session = &config.session;
    assert_eq!((session.lifetime, session.messages), (7_200_000, 50));
    assert_eq!(
        [
            session.handshake,
            session.auth,
            session.idle,
            session.data,
            session.session,
            session.drain
        ],
        [5, 20, 60, 120, 1800, 10].map(Duration::from_secs)
    );
    let limits = config.limits;
    assert_eq!(
        (
            limits.sessions,
            limits.per_net,
            limits.net_failures,
            limits.wide_failures
        ),
        (200, 4, 3, 9)
    );
    assert_eq!(
        (limits.ban, limits.leak, limits.ask),
        (
            Duration::from_secs(3600),
            Duration::from_secs(30),
            Duration::from_secs(2)
        )
    );
    assert_eq!((limits.entries, limits.budget), (1000, 16 << 20));
    assert_eq!(config.listen.len(), 2);
    assert!(config.listen[1].implicit);
}

#[test]
fn mistakes_are_refused_with_their_place() {
    assert_eq!(
        error(&MINIMAL.replace("id = 7", "id = 7\nport = 25")),
        "line 4, column 1: `port` is not a known setting"
    );
    assert_eq!(
        error(&MINIMAL.replace("[keys]", "[queue]\n[keys]")),
        "line 9, column 1: [queue] is not a known section"
    );
    assert_eq!(
        error(&MINIMAL.replace("id = 7", "id = -1")),
        "line 3, column 1: `id` must be between 0 and 4294967295"
    );
    assert_eq!(
        error(&MINIMAL.replace("mx.example.org", "mx..example")),
        "line 4, column 1: `name` must be a host name"
    );
    assert_eq!(
        error(&MINIMAL.replace("/var/lib/bunzzle", "data")),
        "line 7, column 1: `path` must be an absolute path"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[intake]\ndrain = \"0s\"\n")),
        "line 19, column 1: `drain` must be more than zero"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[guard]\nbudget = \"4KiB\"\n")),
        "line 19, column 1: `budget` must be between 1048576 and 1099511627776 bytes"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[[listen]]\naddress = \"0.0.0.0:25\"\n")),
        "line 19, column 1: `address` is listed twice"
    );
    assert_eq!(
        error(&format!("{MINIMAL}mode = \"tls\"\n")),
        "line 18, column 1: `mode` must be \"starttls\" or \"implicit\""
    );
    assert_eq!(
        error(&MINIMAL.replace("0.0.0.0:25", "localhost:25")),
        "line 17, column 1: `address` must be an address such as \"0.0.0.0:25\" or \"[::]:25\""
    );
    assert_eq!(
        error(&MINIMAL.replace("key = \"/etc/bunzzle/key.pem\"", "")),
        "line 12, column 1: missing `key` in [tls]"
    );
    let start = MINIMAL.find("[[listen]]").expect("listen");
    assert_eq!(
        error(&MINIMAL[..start]),
        "line 1, column 1: missing [[listen]]"
    );
    assert_eq!(
        error(&MINIMAL.replace("[store]", "[stores]")),
        "line 1, column 1: missing [store]"
    );
}

#[test]
fn key_file_needs_owner_only_mode() {
    let dir = scratch("key");
    let path = dir.join("key.pem");
    let euid = sys::process::euid();
    for mode in [0o600, 0o400] {
        write(&path, KEY, mode);
        assert_eq!(key_file(&path, euid).expect("key"), KEY);
    }
    for mode in [0o640, 0o604, 0o700, 0o644] {
        write(&path, KEY, mode);
        let error = key_file(&path, euid).expect_err("mode");
        assert!(error.ends_with("must have mode 0600 or 0400"), "{error}");
    }
    write(&path, KEY, 0o600);
    let error = key_file(&path, euid.wrapping_add(1)).expect_err("owner");
    assert!(error.ends_with("belongs to another user"), "{error}");
    let error = key_file(&dir, euid).expect_err("dir");
    assert!(error.ends_with("is not a file"), "{error}");
    write(&path, &vec![b'a'; (1 << 20) + 1], 0o600);
    let error = key_file(&path, euid).expect_err("size");
    assert!(error.ends_with("is too large"), "{error}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn check_reads_the_config_and_the_certificate_pair() {
    let dir = scratch("check");
    let (chain, key, file) = (
        dir.join("chain.pem"),
        dir.join("key.pem"),
        dir.join("bunzzle.toml"),
    );
    write(&chain, CHAIN, 0o644);
    write(&key, KEY, 0o600);
    let text = MINIMAL
        .replace("/etc/bunzzle/chain.pem", &chain.display().to_string())
        .replace("/etc/bunzzle/key.pem", &key.display().to_string());
    write(&file, text.as_bytes(), 0o644);
    let config = check(&file).expect("check");
    assert_eq!(config.tls.key, key);

    write(&key, KEY, 0o644);
    let error = check(&file).expect_err("mode");
    assert!(error.ends_with("must have mode 0600 or 0400"), "{error}");

    write(&key, b"not a key", 0o600);
    let error = check(&file).expect_err("pair");
    assert!(
        error.starts_with(&format!("{} and {}: ", chain.display(), key.display())),
        "{error}"
    );

    write(&file, b"[node]\nid = \"7\"\n", 0o644);
    let error = check(&file).expect_err("config");
    assert_eq!(
        error,
        format!(
            "{}: line 2, column 1: `id` must be an integer, found a string",
            file.display()
        )
    );
    let _ = fs::remove_dir_all(&dir);
}
