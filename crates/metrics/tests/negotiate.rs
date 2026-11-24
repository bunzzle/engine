use metrics::{Format, negotiate};

fn pick(accept: &str) -> Format {
    negotiate(Some(accept.as_bytes()))
}

#[test]
fn defaults_to_text() {
    assert_eq!(negotiate(None), Format::Text);
    assert_eq!(pick(""), Format::Text);
    assert_eq!(pick("application/json"), Format::Text);
    assert_eq!(pick("*/*"), Format::Text);
}

#[test]
fn scrapers() {
    let current = "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.5,\
        application/openmetrics-text;version=0.0.1;q=0.4,\
        text/plain;version=1.0.0;escaping=allow-utf-8;q=0.3,\
        text/plain;version=0.0.4;q=0.2,*/*;q=0.1";
    assert_eq!(pick(current), Format::OpenMetrics);
    let older =
        "application/openmetrics-text; version=0.0.1,text/plain;version=0.0.4;q=0.5,*/*;q=0.1";
    assert_eq!(pick(older), Format::Text);
    assert_eq!(pick("text/plain;version=0.0.4"), Format::Text);
}

#[test]
fn quality_decides() {
    assert_eq!(pick("APPLICATION/OpenMetrics-Text"), Format::OpenMetrics);
    assert_eq!(
        pick("text/plain;q=0.9, application/openmetrics-text"),
        Format::OpenMetrics
    );
    assert_eq!(
        pick("text/plain, application/openmetrics-text;q=0.9"),
        Format::Text
    );
    assert_eq!(pick("application/openmetrics-text;q=0"), Format::Text);
    assert_eq!(
        pick("application/openmetrics-text;version=\"1.0.0\";q=1.000"),
        Format::OpenMetrics
    );
    assert_eq!(
        pick("text/plain;q=0.5,application/openmetrics-text;q=0.5"),
        Format::Text
    );
}

#[test]
fn bad_ranges_are_skipped() {
    for bad in [
        "application/openmetrics-text;q=2",
        "application/openmetrics-text;q=1.5",
        "application/openmetrics-text;q=0.1234",
        "application/openmetrics-text;q=abc",
        "application/openmetrics-text;q=",
        "application/openmetrics-text;version",
        "application/openmetrics-text;q=-0.5",
    ] {
        assert_eq!(pick(bad), Format::Text, "{bad}");
    }
    let many = "x/y,".repeat(40) + "application/openmetrics-text";
    assert_eq!(pick(&many), Format::Text);
    let bytes = [0xff, b',', 0xfe, b';', b'q'];
    assert_eq!(negotiate(Some(&bytes)), Format::Text);
}
