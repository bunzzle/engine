use std::sync::Arc;

use metrics::{Board, Def, Format, Kind, Slab};

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

static LATENCY: [Def; 2] = [
    Def {
        name: "sync_seconds",
        help: "Sync time",
        kind: Kind::Histogram(&[50, 1_000, 2_500_000]),
    },
    Def {
        name: "failed",
        help: "Failed flag",
        kind: Kind::Gauge,
    },
];

fn histogram_board() -> Board {
    static ONE: [Def; 1] = [Def {
        name: "wait_seconds",
        help: "Wait time",
        kind: Kind::Histogram(&[1_000_000]),
    }];
    let node = Arc::new(Slab::new(&LATENCY).expect("valid"));
    let board = Board::new("bunzzle", &ONE, 2)
        .expect("valid")
        .with_node(Arc::clone(&node))
        .expect("valid");
    let core = board.slab(0).expect("core 0");
    core.observe(0, 1_000_000);
    core.observe(0, 1_000_001);
    core.publish(1_000);
    for micros in [0, 50, 51, 900, 3_000_000] {
        node.observe(0, micros);
    }
    node.set(1, 1);
    node.publish(1_000);
    board
}

#[test]
fn histograms_and_node_families() {
    let mut out = String::new();
    histogram_board().render(Format::Text, 1_000, 3_000, &mut out);
    let expected = "\
# HELP bunzzle_wait_seconds Wait time
# TYPE bunzzle_wait_seconds histogram
bunzzle_wait_seconds_bucket{core=\"0\",le=\"1.0\"} 1
bunzzle_wait_seconds_bucket{core=\"0\",le=\"+Inf\"} 2
bunzzle_wait_seconds_sum{core=\"0\"} 2.000001
bunzzle_wait_seconds_count{core=\"0\"} 2
# HELP bunzzle_sync_seconds Sync time
# TYPE bunzzle_sync_seconds histogram
bunzzle_sync_seconds_bucket{le=\"0.00005\"} 2
bunzzle_sync_seconds_bucket{le=\"0.001\"} 4
bunzzle_sync_seconds_bucket{le=\"2.5\"} 4
bunzzle_sync_seconds_bucket{le=\"+Inf\"} 5
bunzzle_sync_seconds_sum 3.001001
bunzzle_sync_seconds_count 5
# HELP bunzzle_failed Failed flag
# TYPE bunzzle_failed gauge
bunzzle_failed 1
# HELP bunzzle_core_up 1 when the core published within the stale window
";
    assert!(out.starts_with(expected), "{out}");
}

#[test]
fn an_unpublished_node_slab_is_left_out() {
    let node = Arc::new(Slab::new(&LATENCY).expect("valid"));
    let board = Board::new("bunzzle", &DEFS, 1)
        .expect("valid")
        .with_node(node)
        .expect("valid");
    let mut out = String::new();
    board.render(Format::OpenMetrics, 0, 0, &mut out);
    assert!(!out.contains("sync_seconds"));
    assert!(!out.contains("bunzzle_failed"));
}
