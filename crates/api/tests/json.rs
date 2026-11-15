use api::json::{Error, Limits, Value, parse};

use crate::common::{Rng, cases};

fn ok(input: &str) -> Value {
    parse(input.as_bytes(), Limits::default()).unwrap_or_else(|e| panic!("{input:?}: {e:?}"))
}

fn bad(input: &[u8]) -> Error {
    match parse(input, Limits::default()) {
        Ok(value) => panic!("{input:?} parsed as {value:?}"),
        Err(e) => e,
    }
}

fn s(text: &str) -> Value {
    Value::String(text.to_owned())
}

#[test]
fn parses_valid_documents() {
    assert_eq!(ok("null"), Value::Null);
    assert_eq!(ok(" \t\r\ntrue \n"), Value::Bool(true));
    assert_eq!(ok("false"), Value::Bool(false));
    assert_eq!(ok("\"\""), s(""));
    assert_eq!(ok("[]"), Value::Array(vec![]));
    assert_eq!(ok("{}"), Value::Object(vec![]));
    assert_eq!(
        ok(r#"{ "a" : [1, -0, 0.5, 1e9, -2E-3, 10.25e+2], "b": {"c": null} }"#),
        Value::Object(vec![
            (
                "a".to_owned(),
                Value::Array(
                    ["1", "-0", "0.5", "1e9", "-2E-3", "10.25e+2"]
                        .iter()
                        .map(|n| Value::Number((*n).to_owned()))
                        .collect()
                )
            ),
            (
                "b".to_owned(),
                Value::Object(vec![("c".to_owned(), Value::Null)])
            ),
        ])
    );
}

#[test]
fn decodes_strings() {
    assert_eq!(ok(r#""a\"\\\/\b\f\n\r\tz""#), s("a\"\\/\u{8}\u{c}\n\r\tz"));
    assert_eq!(ok(r#""\u00e9\u20AC""#), s("é€"));
    assert_eq!(ok(r#""\ud83d\ude00""#), s("😀"));
    assert_eq!(ok("\"caf\u{e9} 😀\""), s("café 😀"));
    assert_eq!(ok(r#""\u0000""#), s("\0"));
}

#[test]
fn refuses_invalid_documents() {
    let cases: [&[u8]; 44] = [
        b"",
        b" ",
        b"nul",
        b"nulls",
        b"True",
        b"[1,]",
        b"[,1]",
        b"[1 2]",
        b"{\"a\":1,}",
        b"{\"a\" 1}",
        b"{a:1}",
        b"{'a':1}",
        b"{\"a\":}",
        b"{1:1}",
        b"[1]]",
        b"[1",
        b"{\"a\":1",
        b"01",
        b"-",
        b"-a",
        b"1.",
        b".5",
        b"1e",
        b"1e+",
        b"+1",
        b"0x1",
        b"NaN",
        b"Infinity",
        b"\"abc",
        b"\"a\nb\"",
        b"\"a\tb\"",
        b"\"\\x\"",
        b"\"\\u12\"",
        b"\"\\u12g4\"",
        b"\"\\ud800\"",
        b"\"\\ud800\\u0041\"",
        b"\"\\udc00\"",
        b"\"\xff\"",
        b"\"\xc3\"",
        b"\xef\xbb\xbf{}",
        b"{} {}",
        b"[1] x",
        b"/* */ 1",
        b"\x001",
    ];
    for input in cases {
        assert!(matches!(bad(input), Error::Syntax(_)), "{input:?}");
    }
}

#[test]
fn refuses_duplicate_keys() {
    assert_eq!(bad(br#"{"a":1,"b":2,"a":3}"#), Error::Duplicate(13));
    assert_eq!(bad(br#"{"a":{"x":1,"x":1}}"#), Error::Duplicate(12));
    assert!(matches!(ok(r#"{"a":{"a":1}}"#), Value::Object(_)));
    let wide: Vec<String> = (0..60_000).map(|i| format!("\"k{i}\":0")).collect();
    let wide = format!("{{{}}}", wide.join(","));
    assert!(matches!(ok(&wide), Value::Object(fields) if fields.len() == 60_000));
    let twice = format!("{}, \"k59999\":1}}", &wide[..wide.len() - 1]);
    assert!(matches!(bad(twice.as_bytes()), Error::Duplicate(_)));
}

#[test]
fn caps_depth_and_values() {
    let limits = Limits::default();
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(parse(deep(limits.depth).as_bytes(), limits).is_ok());
    assert_eq!(
        parse(deep(limits.depth + 1).as_bytes(), limits),
        Err(Error::Depth)
    );
    assert_eq!(parse(deep(100_000).as_bytes(), limits), Err(Error::Depth));
    let objects = format!(
        "{}1{}",
        "{\"a\":".repeat(limits.depth + 1),
        "}".repeat(limits.depth + 1)
    );
    assert_eq!(parse(objects.as_bytes(), limits), Err(Error::Depth));
    let small = Limits {
        depth: 4,
        values: 4,
    };
    assert!(parse(b"[1,2,3]", small).is_ok());
    assert_eq!(parse(b"[1,2,3,4]", small), Err(Error::Values));
}

#[test]
fn reads_typed_fields() {
    let value = ok(
        r#"{"n": 42, "f": 1.5, "neg": -1, "big": 99999999999999999999, "s": "x", "b": true, "l": [1]}"#,
    );
    assert_eq!(value.get("n").and_then(Value::as_u64), Some(42));
    assert_eq!(value.get("f").and_then(Value::as_u64), None);
    assert_eq!(value.get("neg").and_then(Value::as_u64), None);
    assert_eq!(value.get("big").and_then(Value::as_u64), None);
    assert_eq!(value.get("s").and_then(Value::as_str), Some("x"));
    assert_eq!(value.get("b").and_then(Value::as_bool), Some(true));
    assert_eq!(
        value.get("l").and_then(Value::as_array).map(<[Value]>::len),
        Some(1)
    );
    assert!(value.get("missing").is_none());
    assert!(value.as_object().is_some());
}

#[test]
fn writes_escaped_output() {
    let value = Value::Object(vec![
        ("id".to_owned(), s("a\"b\\c\n\r\t\u{1}\u{7f}é")),
        ("n".to_owned(), Value::Number("7".to_owned())),
        (
            "l".to_owned(),
            Value::Array(vec![Value::Null, Value::Bool(false)]),
        ),
    ]);
    let text = value.to_json();
    assert_eq!(
        text,
        "{\"id\":\"a\\\"b\\\\c\\n\\r\\t\\u0001\\u007fé\",\"n\":7,\"l\":[null,false]}"
    );
    assert_eq!(ok(&text), value);
}

fn random_string(rng: &mut Rng) -> String {
    let chars = [
        'a', 'Z', '"', '\\', '/', '\n', '\u{0}', '\u{1f}', 'é', '€', '😀', ' ',
    ];
    (0..rng.below(8))
        .map(|_| chars[rng.below(chars.len())])
        .collect()
}

fn random_value(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(if depth > 4 { 4 } else { 6 }) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => Value::Number(
            ["0", "-1", "12.5", "3e-7", "18446744073709551615"][rng.below(5)].to_owned(),
        ),
        3 => Value::String(random_string(rng)),
        4 => Value::Array(
            (0..rng.below(4))
                .map(|_| random_value(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut fields: Vec<(String, Value)> = Vec::new();
            for _ in 0..rng.below(4) {
                let key = random_string(rng);
                if fields.iter().all(|(k, _)| *k != key) {
                    fields.push((key, random_value(rng, depth + 1)));
                }
            }
            Value::Object(fields)
        }
    }
}

#[test]
fn written_values_parse_back() {
    for mut rng in cases(3000) {
        let value = random_value(&mut rng, 0);
        let text = value.to_json();
        assert_eq!(
            parse(text.as_bytes(), Limits::default()),
            Ok(value),
            "{text}"
        );
    }
}

#[test]
fn random_bytes_never_break_the_parser() {
    let parts: [&[u8]; 16] = [
        b"{", b"}", b"[", b"]", b":", b",", b"\"", b"\\", b"u", b"d8", b"0", b"-", b"e", b"true",
        b" ", b"a",
    ];
    for mut rng in cases(5000) {
        let mut input = Vec::new();
        for _ in 0..rng.below(40) {
            if rng.below(8) == 0 {
                input.push(u8::try_from(rng.below(256)).expect("byte"));
            } else {
                input.extend_from_slice(parts[rng.below(parts.len())]);
            }
        }
        if let Ok(value) = parse(&input, Limits::default()) {
            assert_eq!(
                parse(value.to_json().as_bytes(), Limits::default()),
                Ok(value)
            );
        }
    }
}
