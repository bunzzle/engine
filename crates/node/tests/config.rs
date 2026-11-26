use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use std::net::SocketAddr;

use node::{Delivery, Listen, Tlsrpt, check, key_file, parse};

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

[dns]
servers = ["127.0.0.1"]

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
    assert_eq!(
        config.dns,
        dns::Settings::new(vec!["127.0.0.1:53".parse().expect("server")])
    );
    assert_eq!(config.tls.roots, None);
    assert_eq!(
        config.delivery,
        Delivery {
            settings: deliver::Settings::new("mx.example.org"),
            connections: 10,
        }
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
fn delivery_settings_are_read() {
    let text = format!(
        r#"{MINIMAL}[deliver]
ehlo = "out.example.org"
connections = 4
deadline = "5m"
wait = "2s"
idle = "10s"
reuse = 20
pooled = 50
dead = "2m"
mta_sts = true
egress = "192.0.2.7"
allow = ["10.0.0.0/8", "fd00::/8"]
eight_bit = "fail"
connect_timeout = "10s"
banner_timeout = "1m"
ehlo_timeout = "2m"
starttls_timeout = "3m"
rset_timeout = "4s"
command_timeout = "4m"
body_timeout = "5m"
final_timeout = "6m"
"#
    )
    .replace(
        "servers = [\"127.0.0.1\"]",
        r#"servers = ["::1", "127.0.0.1:5353", "::1"]
dnssec = true
timeout = "3s"
tries = 2
cache = 500"#,
    )
    .replace(
        "key = \"/etc/bunzzle/key.pem\"",
        "key = \"/etc/bunzzle/key.pem\"\nroots = \"/etc/ssl/roots.pem\"",
    );
    let config = parse(&text).expect("config");
    let dns = &config.dns;
    assert_eq!(
        dns.servers,
        ["[::1]:53", "127.0.0.1:5353"].map(|s| s.parse::<SocketAddr>().expect("server"))
    );
    assert_eq!(
        (dns.dnssec, dns.timeout, dns.tries, dns.cache),
        (true, Duration::from_secs(3), 2, 500)
    );
    assert_eq!(
        config.tls.roots.as_deref(),
        Some(Path::new("/etc/ssl/roots.pem"))
    );
    let delivery = &config.delivery;
    let settings = &delivery.settings;
    assert_eq!(
        (settings.ehlo.as_str(), delivery.connections),
        ("out.example.org", 4)
    );
    assert_eq!(
        [
            settings.deadline,
            settings.wait,
            settings.idle,
            settings.dead
        ],
        [300, 2, 10, 120].map(Duration::from_secs)
    );
    assert_eq!((settings.reuse, settings.pooled), (20, 50));
    assert!(settings.mta_sts);
    assert_eq!(settings.egress, Some("192.0.2.7".parse().expect("ip")));
    assert_eq!(
        settings.allow,
        [
            deliver::Cidr::parse("10.0.0.0/8").expect("cidr"),
            deliver::Cidr::parse("fd00::/8").expect("cidr"),
        ]
    );
    assert_eq!(settings.eight_bit, deliver::EightBit::Fail);
    let t = settings.timeouts;
    assert_eq!(
        [
            t.connect,
            t.banner,
            t.ehlo,
            t.starttls,
            t.rset,
            t.command,
            t.body,
            t.final_reply
        ],
        [10, 60, 120, 180, 4, 240, 300, 360].map(Duration::from_secs)
    );
}

#[test]
fn tls_report_settings_are_read() {
    let roots = |text: String| {
        text.replace(
            "key = \"/etc/bunzzle/key.pem\"",
            "key = \"/etc/bunzzle/key.pem\"\nroots = \"/etc/ssl/roots.pem\"",
        )
    };
    let on = roots(format!(
        r#"{MINIMAL}[tlsrpt]
on = true
tenant = 3
from = "tlsrpt@Ops.Example"
organization = "Example Ops"
contact = "mailto:postmaster@ops.example"
"#
    ));
    let config = parse(&on).expect("config");
    assert_eq!(
        config.tlsrpt,
        Some(Tlsrpt {
            tenant: 3,
            from: "tlsrpt@Ops.Example".into(),
        })
    );
    let settings = &config.delivery.settings;
    assert!(settings.tlsrpt);
    assert_eq!(settings.report_tenant, Some(3));
    assert_eq!(
        settings.reporter,
        deliver::Reporter {
            from: "tlsrpt@Ops.Example".into(),
            organization: "Example Ops".into(),
            contact: "mailto:postmaster@ops.example".into(),
            submitter: "ops.example".into(),
        }
    );
    let off = parse(&format!("{MINIMAL}[tlsrpt]\non = false\n")).expect("config");
    assert_eq!(off.tlsrpt, None);
    assert!(!off.delivery.settings.tlsrpt);
    assert_eq!(
        error(&format!("{MINIMAL}[tlsrpt]\non = true\n")),
        "line 22, column 1: `on` needs `roots` in [tls]"
    );
    let bad = roots(format!(
        "{MINIMAL}[tlsrpt]\non = true\ntenant = 3\nfrom = \"nobody\"\norganization = \"x\"\ncontact = \"y\"\n"
    ));
    assert!(parse(&bad).is_err());
    let missing = roots(format!("{MINIMAL}[tlsrpt]\non = true\ntenant = 3\n"));
    assert!(parse(&missing).is_err());
}

#[test]
fn egress_must_be_a_unicast_address() {
    for (line, want) in [
        ("egress = \"mx.example\"", "`egress` must be an IP address"),
        ("egress = \"0.0.0.0\"", "`egress` must be a unicast address"),
        ("egress = \"ff02::1\"", "`egress` must be a unicast address"),
    ] {
        assert_eq!(
            error(&format!("{MINIMAL}[deliver]\n{line}\n")),
            format!("line 22, column 1: {want}")
        );
    }
}

#[test]
fn deliver_nat64_prefixes_parse() {
    let config = parse(&format!(
        "{MINIMAL}[deliver]\nnat64 = [\"2001:db8:64::/96\", \"2001:db8:100::/40\"]\n"
    ))
    .expect("config");
    assert_eq!(
        config.delivery.settings.nat64,
        [
            deliver::Cidr::nat64("2001:db8:64::/96").expect("prefix"),
            deliver::Cidr::nat64("2001:db8:100::/40").expect("prefix"),
        ]
    );
    assert_eq!(
        error(&format!(
            "{MINIMAL}[deliver]\nnat64 = [\"2001:db8::/33\"]\n"
        )),
        "line 22, column 1: `nat64` `2001:db8::/33` must be an IPv6 prefix of length 32, 40, 48, 56, 64 or 96"
    );
}

#[test]
fn deliver_allow_rejects_a_bad_cidr() {
    assert_eq!(
        error(&format!("{MINIMAL}[deliver]\nallow = [\"10.0.0.0/33\"]\n")),
        "line 22, column 1: `allow` `10.0.0.0/33` must be an address or CIDR"
    );
}

#[test]
fn deliver_site_rules_are_read() {
    let text = format!(
        "{MINIMAL}[deliver]\n[[deliver.site]]\nname = \"google\"\nsuffix = [\"Google.COM\", \"googlemail.com\"]\n[[deliver.site]]\nname = \"microsoft\"\nsuffix = [\"outlook.com\"]\n"
    );
    let config = parse(&text).expect("config");
    assert_eq!(
        config.delivery.settings.sites,
        [
            deliver::Site::new(
                "google",
                ["google.com", "googlemail.com"].map(str::to_owned).into()
            ),
            deliver::Site::new("microsoft", ["outlook.com"].map(str::to_owned).into()),
        ]
    );
}

#[test]
fn deliver_site_rules_are_checked() {
    let base = format!("{MINIMAL}[deliver]\n");
    let cases = [
        (
            "[[deliver.site]]\nname = \"google\"\nsuffix = []\n",
            "`suffix` must list at least one host name",
        ),
        (
            "[[deliver.site]]\nname = \"google\"\nsuffix = [\"goo..gle.com\"]\n",
            "`suffix` must list host names",
        ),
        (
            "[[deliver.site]]\nname = \"google\"\nsuffix = [\"google.com\"]\n[[deliver.site]]\nname = \"google\"\nsuffix = [\"gmail.com\"]\n",
            "`name` is listed twice",
        ),
        (
            "[[deliver.site]]\nname = \"\"\nsuffix = [\"google.com\"]\n",
            "`name` must be between 1 and 255 bytes",
        ),
        (
            "[[deliver.site]]\nsuffix = [\"google.com\"]\n",
            "missing `name`",
        ),
        (
            "[[deliver.site]]\nname = \"google\"\nsuffix = [\"google.com\"]\nextra = 1\n",
            "`extra` is not a known setting",
        ),
    ];
    for (section, want) in cases {
        let text = error(&format!("{base}{section}"));
        assert!(text.contains(want), "{section}: {text}");
    }
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
        "line 22, column 1: `drain` must be more than zero"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[guard]\nbudget = \"4KiB\"\n")),
        "line 22, column 1: `budget` must be between 1048576 and 1099511627776 bytes"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[[listen]]\naddress = \"0.0.0.0:25\"\n")),
        "line 22, column 1: `address` is listed twice"
    );
    assert_eq!(
        error(&format!("{MINIMAL}mode = \"tls\"\n")),
        "line 21, column 1: `mode` must be \"starttls\" or \"implicit\""
    );
    assert_eq!(
        error(&MINIMAL.replace("0.0.0.0:25", "localhost:25")),
        "line 20, column 1: `address` must be an address such as \"0.0.0.0:25\" or \"[::]:25\""
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
    assert_eq!(
        error(&MINIMAL.replace("[dns]", "[resolver]")),
        "line 1, column 1: missing [dns]"
    );
    let dns = [
        (
            "servers = []",
            "line 17, column 1: `servers` must list at least one server",
        ),
        (
            "servers = [\"localhost\"]",
            "line 17, column 1: `servers` must list addresses such as \"127.0.0.1\" or \"[::1]:53\"",
        ),
        (
            "servers = [\"10.0.0.1\"]\ndnssec = true",
            "line 18, column 1: `dnssec` needs every server on loopback",
        ),
    ];
    for (from, want) in dns {
        assert_eq!(
            error(&MINIMAL.replace("servers = [\"127.0.0.1\"]", from)),
            want
        );
    }
    let deliver = [
        ("ehlo = \"a..b\"", "`ehlo` must be a host name"),
        (
            "connections = 0",
            "`connections` must be between 1 and 100000",
        ),
        (
            "deadline = \"10m\"",
            "`deadline` must be more than zero and at most 9m",
        ),
        ("mta_sts = true", "`mta_sts` needs `roots` in [tls]"),
        (
            "eight_bit = \"drop\"",
            "`eight_bit` must be \"send\" or \"fail\"",
        ),
        ("retries = 3", "`retries` is not a known setting"),
    ];
    for (line, want) in deliver {
        assert_eq!(
            error(&format!("{MINIMAL}[deliver]\n{line}\n")),
            format!("line 22, column 1: {want}")
        );
    }
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

    let roots = dir.join("roots.pem");
    let with_roots = text.replace(
        "key = \"",
        &format!("roots = \"{}\"\nkey = \"", roots.display()),
    );
    write(&file, with_roots.as_bytes(), 0o644);
    write(&roots, CHAIN, 0o644);
    assert_eq!(check(&file).expect("roots").tls.roots, Some(roots.clone()));
    write(&roots, b"", 0o644);
    let error = check(&file).expect_err("no roots");
    assert!(
        error.starts_with(&format!("{}: ", roots.display())),
        "{error}"
    );
    write(&file, text.as_bytes(), 0o644);

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

#[test]
fn metrics_settings_are_read() {
    assert!(parse(MINIMAL).expect("config").metrics.is_none());
    let text = format!("{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\", \"10.0.0.1:9464\"]\n");
    let metrics = parse(&text).expect("config").metrics.expect("metrics");
    assert_eq!(metrics.listen.len(), 2);
    assert_eq!(metrics.interval, Duration::from_secs(1));
    let text = format!("{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\"]\ninterval = \"5s\"\n");
    let metrics = parse(&text).expect("config").metrics.expect("metrics");
    assert_eq!(metrics.interval, Duration::from_secs(5));

    assert_eq!(
        error(&format!("{MINIMAL}[metrics]\ninterval = \"5s\"\n")),
        "line 1, column 1: [metrics] needs `listen`"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[metrics]\nlisten = [\"0.0.0.0:25\"]\n")),
        "line 22, column 1: `listen` lists an address twice"
    );
    assert_eq!(
        error(&format!(
            "{MINIMAL}[api]\nplain = [\"127.0.0.1:8080\"]\n[metrics]\nlisten = [\"127.0.0.1:8080\"]\n"
        )),
        "line 24, column 1: `listen` lists an address twice"
    );
    assert_eq!(
        error(&format!(
            "{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\"]\ninterval = \"500ms\"\n"
        )),
        "line 23, column 1: `interval` must be between 1s and 60s"
    );
    assert_eq!(
        error(&format!(
            "{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\"]\ninterval = \"2m\"\n"
        )),
        "line 23, column 1: `interval` must be between 1s and 60s"
    );
    assert!(
        error(&format!(
            "{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\"]\nport = 1\n"
        ))
        .contains("port")
    );
}

#[test]
fn metric_tenants_are_read() {
    let base = format!("{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\"]\n");
    let metrics = parse(&base).expect("config").metrics.expect("metrics");
    assert_eq!(metrics.tenants, Vec::<u32>::new());
    let metrics = parse(&format!("{base}tenants = [7, 4294967295, 1]\n"))
        .expect("config")
        .metrics
        .expect("metrics");
    assert_eq!(metrics.tenants, vec![7, u32::MAX, 1]);
    let many: Vec<String> = (1..=65).map(|n| n.to_string()).collect();
    let cases = [
        ("tenants = [3, 3]".to_owned(), "lists a tenant twice"),
        (
            "tenants = [0]".to_owned(),
            "must list ids between 1 and 4294967295",
        ),
        (
            "tenants = [4294967296]".to_owned(),
            "must list ids between 1 and 4294967295",
        ),
        (
            "tenants = [-1]".to_owned(),
            "must list ids between 1 and 4294967295",
        ),
        (
            "tenants = [\"7\"]".to_owned(),
            "must be an array of tenant ids",
        ),
        ("tenants = 7".to_owned(), "must be an array of tenant ids"),
        (
            format!("tenants = [{}]", many.join(", ")),
            "lists more than 64 tenants",
        ),
    ];
    for (line, message) in cases {
        let text = error(&format!("{base}{line}\n"));
        assert!(text.contains(message), "{line}: {text}");
    }
    let open = "needs every metrics `listen` address on loopback or a private network";
    for listen in [
        "0.0.0.0:9464",
        "203.0.113.5:9464",
        "[::]:9464",
        "[2001:db8::1]:9464",
    ] {
        let text = error(&format!(
            "{MINIMAL}[metrics]\nlisten = [\"127.0.0.1:9464\", \"{listen}\"]\ntenants = [7]\n"
        ));
        assert!(text.contains(open), "{listen}: {text}");
    }
    for listen in [
        "10.1.2.3:9464",
        "172.16.0.9:9464",
        "192.168.1.1:9464",
        "[::1]:9464",
        "[fd00::9]:9464",
    ] {
        let text = format!("{MINIMAL}[metrics]\nlisten = [\"{listen}\"]\ntenants = [7]\n");
        assert!(parse(&text).is_ok(), "{listen}");
    }
    let text = format!("{MINIMAL}[metrics]\nlisten = [\"0.0.0.0:9464\"]\ntenants = []\n");
    assert!(parse(&text).is_ok());
    let most: Vec<String> = (1..=64).map(|n| n.to_string()).collect();
    let metrics = parse(&format!("{base}tenants = [{}]\n", most.join(", ")))
        .expect("config")
        .metrics
        .expect("metrics");
    assert_eq!(metrics.tenants.len(), 64);
}

#[test]
fn api_settings_are_read() {
    assert!(parse(MINIMAL).expect("config").api.is_none());
    let text = format!(
        "{MINIMAL}[api]\nlisten = [\"0.0.0.0:443\"]\nplain = [\"127.0.0.1:8080\"]\n\
         max_body = \"2MiB\"\nrequests = 50\nhandshake = \"5s\"\nhead = \"4s\"\nbody = \"20s\"\n\
         idle = \"30s\"\ndrain = \"10s\"\n"
    );
    let api = parse(&text).expect("config").api.expect("api");
    assert_eq!(
        api.listen,
        ["0.0.0.0:443".parse::<SocketAddr>().expect("address")]
    );
    assert_eq!(
        api.plain,
        ["127.0.0.1:8080".parse::<SocketAddr>().expect("address")]
    );
    let settings = api.settings;
    assert_eq!(settings.name, "mx.example.org");
    assert_eq!(settings.max_body, Some(2 << 20));
    assert_eq!(settings.limits.requests, 50);
    assert_eq!(
        (
            settings.timeouts.handshake,
            settings.timeouts.head,
            settings.timeouts.body,
            settings.timeouts.idle,
            settings.drain
        ),
        (
            Duration::from_secs(5),
            Duration::from_secs(4),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::from_secs(10)
        )
    );

    assert_eq!(
        error(&format!("{MINIMAL}[api]\nplain = [\"0.0.0.0:8080\"]\n")),
        "line 22, column 1: `plain` must list loopback addresses only"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[api]\nlisten = [\"0.0.0.0:25\"]\n")),
        "line 22, column 1: `listen` lists an address twice"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[api]\nmax_body = \"1KiB\"\n")),
        "line 1, column 1: [api] needs `listen` or `plain`"
    );
    assert_eq!(
        error(&format!(
            "{MINIMAL}[api]\nlisten = [\"0.0.0.0:443\"]\nmax_body = \"10B\"\n"
        )),
        "line 23, column 1: `max_body` must be between 1024 and 17179869184 bytes"
    );
}

#[test]
fn webhook_settings_are_read() {
    let with_roots = |text: String| {
        text.replace(
            "key = \"/etc/bunzzle/key.pem\"",
            "key = \"/etc/bunzzle/key.pem\"\nroots = \"/etc/ssl/roots.pem\"",
        )
    };
    assert_eq!(
        parse(MINIMAL).expect("config").webhooks,
        deliver::HookSettings::default()
    );
    assert_eq!(
        error(&format!("{MINIMAL}[webhooks]\n")),
        "line 21, column 1: [webhooks] needs `roots` in [tls]"
    );
    let config = parse(&with_roots(format!(
        "{MINIMAL}[webhooks]\negress = \"192.0.2.9\"\nallow = [\"10.0.0.0/8\", \"fd00::/8\", \"192.168.4.1\"]\nnat64 = [\"2001:db8:64::/96\"]\n"
    )))
    .expect("config");
    assert_eq!(
        config.webhooks.egress,
        Some("192.0.2.9".parse().expect("address"))
    );
    assert_eq!(
        config.webhooks.allow,
        [
            deliver::Cidr::parse("10.0.0.0/8").expect("cidr"),
            deliver::Cidr::parse("fd00::/8").expect("cidr"),
            deliver::Cidr::parse("192.168.4.1").expect("cidr"),
        ]
    );
    assert_eq!(
        config.webhooks.nat64,
        [deliver::Cidr::nat64("2001:db8:64::/96").expect("prefix")]
    );
    assert_eq!(
        error(&with_roots(format!(
            "{MINIMAL}[webhooks]\nallow = [\"10.0.0.0/33\"]\n"
        ))),
        "line 23, column 1: `allow` `10.0.0.0/33` must be an address or CIDR"
    );
    assert_eq!(
        error(&with_roots(format!(
            "{MINIMAL}[webhooks]\negress = \"::1x\"\n"
        ))),
        "line 23, column 1: `egress` must be an IP address"
    );
    assert_eq!(
        error(&with_roots(format!(
            "{MINIMAL}[webhooks]\negress = \"0.0.0.0\"\n"
        ))),
        "line 23, column 1: `egress` must be a unicast address"
    );
}

#[test]
fn admin_settings_are_read() {
    assert!(parse(MINIMAL).expect("config").admin.is_none());
    let text = format!("{MINIMAL}[admin]\nsocket = \"/run/bunzzle/admin.sock\"\n");
    let admin = parse(&text).expect("config").admin.expect("admin");
    assert_eq!(admin.socket, Path::new("/run/bunzzle/admin.sock"));
    assert_eq!(
        error(&format!(
            "{MINIMAL}[admin]\nsocket = \"/run/bunzzle/keys.sock\"\n"
        )),
        "line 22, column 1: `socket` must differ from the keys socket"
    );
    assert_eq!(
        error(&format!("{MINIMAL}[admin]\nsocket = \"admin.sock\"\n")),
        "line 22, column 1: `socket` must be an absolute path"
    );
    assert!(error(&format!("{MINIMAL}[admin]\n")).contains("socket"));
    assert!(error(&format!("{MINIMAL}[admin]\nsocket = \"/a\"\nother = 1\n")).contains("other"));
}
