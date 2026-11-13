use std::time::Duration;

use config::{Error, Value, duration, parse, size};

const NODE: &str = "# node\r
[node]\r
id = 3\r
name = \"mx1.example.org\"   # host name\r
cores = 4\r
\r
[store]\r
path = \"/var/lib/bunzzle/data\"\r
flush = 1_000\r
\r
[intake.limits]\r
drain = \"30s\"\r
budget = \"64MiB\"\r
\r
[[listen]]\r
address = \"0.0.0.0:587\"\r
mode = \"starttls\"\r
\r
[[listen]]\r
address = \"[::]:465\"\r
mode = \"implicit\"\r
ports = [465, 466,]\r
tags = []\r
";

fn fails(text: &str) -> Error {
    parse(text).expect_err("must fail")
}

fn at(text: &str) -> (usize, usize, String) {
    let error = fails(text);
    (error.line, error.column, error.message)
}

#[test]
fn reads_a_node_file() {
    let mut root = parse(NODE).expect("parse");
    let mut node = root.table("node").expect("node");
    assert_eq!(node.require("id").expect("id").number(1, 1000), Ok(3));
    assert_eq!(
        node.require("name").expect("name").str(),
        Ok("mx1.example.org")
    );
    assert_eq!(node.require("cores").expect("cores").int(), Ok(4));
    node.finish().expect("node done");
    let mut intake = root.table("intake").expect("intake");
    let mut limits = intake.table("limits").expect("limits");
    assert_eq!(limits.line(), 11);
    assert_eq!(limits.name(), "intake.limits");
    assert_eq!(
        limits.require("drain").expect("drain").duration(),
        Ok(Duration::from_secs(30))
    );
    assert_eq!(
        limits.require("budget").expect("budget").size(),
        Ok(64 << 20)
    );
    let listens = root.tables("listen");
    assert_eq!(listens.len(), 2);
    let mut second = listens.into_iter().nth(1).expect("second");
    assert_eq!(second.line(), 19);
    assert_eq!(
        second.take("ports").map(|e| e.value().clone()),
        Some(Value::Array(vec![Value::Int(465), Value::Int(466)]))
    );
    assert_eq!(second.take("tags").expect("tags").strs(), Ok(vec![]));
    let error = second.finish().expect_err("address and mode left");
    assert_eq!((error.line, error.column), (20, 1));
    assert_eq!(error.message, "`address` is not a known setting");
    let error = root.finish().expect_err("store left");
    assert_eq!(error.message, "[store] is not a known section");
}

#[test]
fn reports_types_ranges_and_missing_keys() {
    let mut root = parse("a = \"x\"\nb = 0\nc = -5\nf = 1_000\n[t]\n").expect("parse");
    let a = root.require("a").expect("a");
    assert_eq!(
        a.int().expect_err("type").to_string(),
        "line 1, column 1: `a` must be an integer, found a string"
    );
    assert_eq!(
        a.duration().expect_err("unit").message,
        "`a` must be a duration such as \"500ms\", \"10s\", \"5m\" or \"2h\""
    );
    let b = root.require("b").expect("b");
    assert_eq!(
        b.number(1, 9).expect_err("low").message,
        "`b` must be between 1 and 9"
    );
    assert_eq!(root.require("c").expect("c").int(), Ok(-5));
    assert_eq!(root.require("f").expect("f").int(), Ok(1000));
    let mut table = root.table("t").expect("t");
    let missing = table.require("d").expect_err("missing");
    assert_eq!(
        (missing.line, missing.message.as_str()),
        (5, "missing `d` in [t]")
    );
    let missing = root.require("e").expect_err("missing");
    assert_eq!(missing.message, "missing `e` in the top level");
}

#[test]
fn refuses_what_is_outside_the_subset() {
    let cases: &[(&str, (usize, usize), &str)] = &[
        (
            "a.b = 1",
            (1, 2),
            "dotted keys are not supported, use a [section]",
        ),
        ("\"a\" = 1", (1, 1), "quoted keys are not supported"),
        (
            "a = 1.5",
            (1, 6),
            "only whole decimal numbers are supported",
        ),
        (
            "a = 0x10",
            (1, 6),
            "only whole decimal numbers are supported",
        ),
        ("a = 1979-05-27", (1, 9), "unexpected `-`"),
        ("a = 007", (1, 5), "leading zeros are not allowed"),
        ("a = 1__0", (1, 7), "`_` must sit between digits"),
        ("a = 10_", (1, 8), "expected digits"),
        ("a = +1", (1, 5), "expected a value, found `+`"),
        ("a = 99999999999999999999", (1, 5), "number out of range"),
        (
            "a = 'x'",
            (1, 5),
            "literal strings are not supported, use \"...\"",
        ),
        (
            "a = \"\"\"x\"\"\"",
            (1, 6),
            "multi-line strings are not supported",
        ),
        ("a = {b = 1}", (1, 5), "inline tables are not supported"),
        ("a = \"x\\u0041\"", (1, 8), "unsupported escape"),
        ("a = \"x\u{1}\"", (1, 7), "control character in a string"),
        ("a = \"x", (1, 7), "unterminated string"),
        ("a = [1, \"x\"]", (1, 9), "arrays must not mix types"),
        ("a = [true]", (1, 6), "arrays hold only strings or integers"),
        ("a = [[1]]", (1, 6), "arrays hold only strings or integers"),
        ("a = [1,", (1, 8), "expected a value"),
        ("a = [1 2]", (1, 8), "expected `,` or `]`, found `2`"),
        ("a = [1", (1, 7), "arrays must close on the same line"),
        ("a = truth", (1, 5), "expected a value"),
        ("a = truer", (1, 9), "unexpected `r`"),
        ("a = 1 b", (1, 7), "unexpected `b`"),
        ("a 1", (1, 3), "expected `=`, found `1`"),
        ("a =", (1, 4), "expected a value"),
        ("a = 1\na = 2", (2, 1), "`a` is set twice"),
        ("[a]\n[a]", (2, 1), "[a] is defined twice"),
        ("[a.b]\n[a]\n[a]", (3, 1), "[a] is defined twice"),
        ("a = 1\n[a]", (2, 1), "`a` is already a value"),
        ("a = 1\n[a.b]", (2, 1), "`a` is already a value"),
        ("[a]\n[[a]]", (2, 1), "[a] is already a table"),
        ("[[a]]\n[a]", (2, 1), "[a] is an array of tables"),
        ("[[a]]\n[a.b]", (2, 1), "[a] is an array of tables"),
        ("[a.b]\n[a]\nb = 1", (3, 1), "`b` is already a section"),
        ("[a", (1, 3), "expected `]` before the end of the line"),
        ("[[a]", (1, 5), "expected `]` before the end of the line"),
        ("[a] x", (1, 5), "unexpected `x`"),
        ("[]", (1, 2), "expected a key, found `]`"),
        ("# a\u{7f}", (1, 4), "control character in a comment"),
        ("a = 1 # \u{0}", (1, 9), "control character in a comment"),
        ("\u{feff}a = 1", (1, 1), "expected a key, found `\u{feff}`"),
    ];
    for (text, place, message) in cases {
        assert_eq!(
            at(text),
            (place.0, place.1, (*message).to_string()),
            "{text:?}"
        );
    }
}

#[test]
fn keeps_implicit_parents_and_arrays_in_order() {
    let mut root = parse("[a.b]\nx = 1\n[a]\ny = 2\n[[l]]\nn = 1\n[[l]]\nn = 2\n").expect("parse");
    let mut a = root.table("a").expect("a");
    assert_eq!(a.line(), 3);
    assert_eq!(a.require("y").expect("y").int(), Ok(2));
    let mut b = a.table("b").expect("b");
    assert_eq!(b.require("x").expect("x").int(), Ok(1));
    let numbers: Vec<i64> = root
        .tables("l")
        .iter_mut()
        .map(|t| t.require("n").expect("n").int().expect("int"))
        .collect();
    assert_eq!(numbers, [1, 2]);
    assert!(root.tables("l").is_empty());
}

#[test]
fn strings_keep_escapes_and_unicode() {
    let mut root = parse("a = \"tab\\there \\\"q\\\" \\\\ é\\n\"").expect("parse");
    assert_eq!(
        root.require("a").expect("a").str(),
        Ok("tab\there \"q\" \\ é\n")
    );
}

#[test]
fn durations_and_sizes() {
    assert_eq!(duration("500ms"), Some(Duration::from_millis(500)));
    assert_eq!(duration("10s"), Some(Duration::from_secs(10)));
    assert_eq!(duration("5m"), Some(Duration::from_secs(300)));
    assert_eq!(duration("2h"), Some(Duration::from_secs(7200)));
    assert_eq!(duration("0s"), Some(Duration::ZERO));
    for bad in ["", "s", "10", "10 s", "1.5s", "010s", "-1s", "10S", "1d"] {
        assert_eq!(duration(bad), None, "{bad:?}");
    }
    assert_eq!(size("512B"), Some(512));
    assert_eq!(size("64KiB"), Some(64 << 10));
    assert_eq!(size("16MiB"), Some(16 << 20));
    assert_eq!(size("1GiB"), Some(1 << 30));
    for bad in ["", "1", "1KB", "1kib", "1 MiB", "99999999999GiB"] {
        assert_eq!(size(bad), None, "{bad:?}");
    }
}
