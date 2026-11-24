use metrics::{Board, Def, Format, Kind};

static DEFS: [Def; 2] = [
    Def {
        name: "sent",
        help: "Messages sent",
        kind: Kind::Counter,
    },
    Def {
        name: "queued",
        help: "Recipients queued",
        kind: Kind::Gauge,
    },
];

fn board() -> Board {
    let board = Board::new("bunzzle", &DEFS, 3).expect("valid");
    let first = board.slab(0).expect("core 0");
    first.set(0, 5);
    first.set(1, 2);
    first.publish(1_000);
    let second = board.slab(1).expect("core 1");
    second.set(0, 8);
    second.publish(500);
    board
}

fn render(format: Format) -> String {
    let mut out = String::new();
    board().render(format, 3_250, 2_500, &mut out);
    out
}

#[test]
fn text() {
    let expected = "\
# HELP bunzzle_sent_total Messages sent
# TYPE bunzzle_sent_total counter
bunzzle_sent_total{core=\"0\"} 5
bunzzle_sent_total{core=\"1\"} 8
# HELP bunzzle_queued Recipients queued
# TYPE bunzzle_queued gauge
bunzzle_queued{core=\"0\"} 2
bunzzle_queued{core=\"1\"} 0
# HELP bunzzle_core_up 1 when the core published within the stale window
# TYPE bunzzle_core_up gauge
bunzzle_core_up{core=\"0\"} 1
bunzzle_core_up{core=\"1\"} 0
bunzzle_core_up{core=\"2\"} 0
# HELP bunzzle_core_publish_age_seconds Seconds since the core last published
# TYPE bunzzle_core_publish_age_seconds gauge
bunzzle_core_publish_age_seconds{core=\"0\"} 2.250
bunzzle_core_publish_age_seconds{core=\"1\"} 2.750
";
    assert_eq!(render(Format::Text), expected);
}

#[test]
fn openmetrics() {
    let out = render(Format::OpenMetrics);
    assert!(out.starts_with(
        "# HELP bunzzle_sent Messages sent\n# TYPE bunzzle_sent counter\nbunzzle_sent_total{core=\"0\"} 5\n"
    ));
    assert!(out.contains("# TYPE bunzzle_queued gauge\nbunzzle_queued{core=\"0\"} 2\n"));
    assert!(out.ends_with("bunzzle_core_publish_age_seconds{core=\"1\"} 2.750\n# EOF\n"));
    assert_eq!(out.matches("# EOF").count(), 1);
}

#[test]
fn a_clock_behind_the_stamp_reads_as_fresh() {
    let mut out = String::new();
    board().render(Format::Text, 0, 0, &mut out);
    assert!(out.contains("bunzzle_core_up{core=\"0\"} 1\n"));
    assert!(out.contains("bunzzle_core_publish_age_seconds{core=\"0\"} 0.000\n"));
}

#[test]
fn content_types() {
    assert_eq!(
        Format::Text.content_type(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert_eq!(
        Format::OpenMetrics.content_type(),
        "application/openmetrics-text; version=1.0.0; charset=utf-8"
    );
}
