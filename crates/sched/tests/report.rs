use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, SimDriver};
use rt::{sleep, spawn, timeout};
use sched::{EventKind, Inbound, Node, Reason, ReportBlock, ReportKind, ReportOutcome};
use spool::MessageId;

use super::index::{
    Cluster, Idle, accept_listed, answering, created, every_event, owned_shard, ready, started,
};

fn setup(seed: u64) -> (Rc<SimDriver>, Cluster) {
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
    let cluster = started(&driver, 2);
    (driver, cluster)
}

async fn source(node: &Node<Idle>, addresses: &[&str]) -> MessageId {
    let shard = owned_shard(node).await;
    let id = accept_listed(node, shard, addresses, u64::MAX / 2).await.0;
    for _ in 0..2_000 {
        if node.spool().tenant(id).is_none() {
            return id;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("message {id:?} never became final");
}

fn block(address: &str, status: (u8, u16, u16), diagnostic: &str) -> ReportBlock {
    ReportBlock {
        address: Some(address.to_owned()),
        status,
        diagnostic: diagnostic.to_owned(),
    }
}

fn inbound(message: MessageId, kind: ReportKind, blocks: Vec<ReportBlock>) -> Inbound {
    Inbound {
        tenant: 1,
        generation: 1,
        message,
        recipient: 0,
        kind,
        blocks,
    }
}

async fn reports(node: &Node<Idle>, message: MessageId, kind: EventKind) -> Vec<sched::EventRead> {
    every_event(node)
        .await
        .into_iter()
        .filter(|read| read.event.message == message && read.event.kind == kind)
        .collect()
}

#[test]
fn single_match_writes_an_event_and_suppression() {
    let (_, cluster) = setup(100);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let id = source(&nodes[0], &["User@Example.ORG"]).await;
        let report = inbound(
            id,
            ReportKind::Bounce,
            vec![
                block("member@example.net", (5, 4, 4), "wrong block"),
                block("user@example.org", (5, 1, 1), "550 mailbox gone"),
            ],
        );
        assert_eq!(nodes[1].report(report).await, Ok(ReportOutcome::Written(1)));
        let events = reports(&nodes[0], id, EventKind::Bounced).await;
        assert_eq!(events.len(), 1);
        let body = events[0].body.as_ref().expect("body");
        assert_eq!(body.address, b"User@Example.ORG");
        assert_eq!(body.reply, b"550 mailbox gone");
        assert_eq!((body.attempts, body.class), (0, 0));
        let suppression = nodes[0]
            .suppressions()
            .get(1, "user@example.org")
            .await
            .expect("get")
            .expect("suppression");
        assert_eq!(suppression.reason, Reason::Bounce);
    });
    cluster.stop();
}

#[test]
fn an_identical_report_is_duplicate_after_a_restart() {
    let (driver, cluster) = setup(110);
    let nodes = cluster.nodes.clone();
    let report = cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let id = source(&nodes[0], &["duplicate@example.org"]).await;
        let report = inbound(
            id,
            ReportKind::Bounce,
            vec![block("duplicate@example.org", (5, 1, 1), "gone")],
        );
        assert_eq!(
            nodes[0].report(report.clone()).await,
            Ok(ReportOutcome::Written(1))
        );
        assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 1);
        report
    });
    drop(cluster);
    let restarted_driver = Rc::new(SimDriver::with_disk(111, Config::default(), driver.crash()));
    let restarted = started(&restarted_driver, 2);
    let nodes = restarted.nodes.clone();
    restarted.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        assert_eq!(
            nodes[1].report(report.clone()).await,
            Ok(ReportOutcome::Duplicate)
        );
        assert_eq!(
            reports(&nodes[0], report.message, EventKind::Bounced)
                .await
                .len(),
            1
        );
    });
    restarted.stop();
}

#[test]
fn concurrent_identical_reports_write_one_event() {
    let (_, cluster) = setup(120);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let id = source(&nodes[0], &["concurrent@example.org"]).await;
        let report = inbound(
            id,
            ReportKind::Bounce,
            vec![block("concurrent@example.org", (5, 1, 1), "gone")],
        );
        let first = spawn({
            let node = nodes[0].clone();
            let report = report.clone();
            async move { node.report(report).await }
        });
        let second = spawn({
            let node = nodes[0].clone();
            async move { node.report(report).await }
        });
        let outcomes = [first.await.expect("first"), second.await.expect("second")];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReportOutcome::Written(1))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReportOutcome::Duplicate)
                .count(),
            1
        );
        assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 1);
    });
    cluster.stop();
}

#[test]
fn a_non_listed_bounce_status_writes_only_an_event() {
    let (_, cluster) = setup(130);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let id = source(&nodes[0], &["status@example.org"]).await;
        let report = inbound(
            id,
            ReportKind::Bounce,
            vec![block("status@example.org", (5, 4, 4), "550 other")],
        );
        assert_eq!(nodes[0].report(report).await, Ok(ReportOutcome::Written(1)));
        assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 1);
        assert_eq!(
            nodes[0]
                .suppressions()
                .get(1, "status@example.org")
                .await
                .expect("get"),
            None
        );
    });
    cluster.stop();
}

#[test]
fn a_list_member_report_does_not_suppress() {
    let (_, cluster) = setup(140);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let id = source(&nodes[0], &["list@example.org"]).await;
        let report = inbound(
            id,
            ReportKind::Bounce,
            vec![block("member@example.net", (5, 1, 1), "member gone")],
        );
        assert_eq!(nodes[0].report(report).await, Ok(ReportOutcome::Written(1)));
        assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 1);
        for address in ["list@example.org", "member@example.net"] {
            assert_eq!(
                nodes[0].suppressions().get(1, address).await.expect("get"),
                None
            );
        }
    });
    cluster.stop();
}

#[test]
fn any_reports_write_events_without_suppressions() {
    let (_, cluster) = setup(150);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let addresses = ["first@example.org", "second@example.org"];
        let id = source(&nodes[0], &addresses).await;
        let mut report = inbound(
            id,
            ReportKind::Bounce,
            addresses
                .iter()
                .map(|address| block(address, (5, 1, 1), "gone"))
                .collect(),
        );
        report.recipient = crypto::ANY;
        assert_eq!(nodes[1].report(report).await, Ok(ReportOutcome::Written(2)));
        assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 2);
        for address in addresses {
            assert_eq!(
                nodes[0].suppressions().get(1, address).await.expect("get"),
                None
            );
        }
    });
    cluster.stop();
}

#[test]
fn separate_any_reports_write_an_event_for_each_recipient() {
    let (_, cluster) = setup(180);
    let nodes = cluster.nodes.clone();
    cluster
        .run(async move {
            timeout(Duration::from_secs(180), async {
                ready(&nodes).await;
                answering(&nodes);
                let addresses = ["first@example.org", "second@example.org"];
                let id = source(&nodes[0], &addresses).await;
                for address in addresses {
                    let mut report = inbound(
                        id,
                        ReportKind::Bounce,
                        vec![block(address, (5, 1, 1), "gone")],
                    );
                    report.recipient = crypto::ANY;
                    assert_eq!(nodes[1].report(report).await, Ok(ReportOutcome::Written(1)));
                }
                let events = reports(&nodes[0], id, EventKind::Bounced).await;
                let mut written: Vec<_> = events
                    .iter()
                    .map(|event| event.body.as_ref().expect("body").address.as_slice())
                    .collect();
                written.sort_unstable();
                assert_eq!(written, addresses.map(str::as_bytes));
            })
            .await
        })
        .expect("report test timed out");
    cluster.stop();
}

#[test]
fn reports_find_a_duplicate_on_a_later_page() {
    let (_, cluster) = setup(190);
    let nodes = cluster.nodes.clone();
    cluster
        .run(async move {
            timeout(Duration::from_mins(20), async {
                ready(&nodes).await;
                answering(&nodes);
                let address = "shared@example.org";
                let node = &nodes[0];
                let shard = owned_shard(node).await;
                let mut ids = Vec::new();
                for _ in 0..101 {
                    let (id, _) = accept_listed(node, shard, &[address], u64::MAX / 2).await;
                    ids.push(id);
                }
                for _ in 0..20_000 {
                    if ids.iter().all(|&id| node.spool().tenant(id).is_none()) {
                        break;
                    }
                    sleep(Duration::from_millis(50)).await;
                }
                let pending = ids
                    .iter()
                    .filter(|&&id| node.spool().tenant(id).is_some())
                    .count();
                assert_eq!(pending, 0, "messages still pending");
                let first = ids[0];
                let last = *ids.last().expect("last message");
                let report = |id| {
                    let mut report = inbound(
                        id,
                        ReportKind::Bounce,
                        vec![block(address, (5, 1, 1), "gone")],
                    );
                    report.recipient = crypto::ANY;
                    report
                };
                for id in [first, last] {
                    assert_eq!(
                        nodes[1].report(report(id)).await,
                        Ok(ReportOutcome::Written(1))
                    );
                }
                assert_eq!(
                    nodes[1].report(report(last)).await,
                    Ok(ReportOutcome::Duplicate)
                );
                for id in [first, last] {
                    assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 1);
                }
            })
            .await
        })
        .expect("report test timed out");
    cluster.stop();
}

#[test]
fn an_any_report_for_another_messages_recipient_is_unmatched() {
    let (_, cluster) = setup(200);
    let nodes = cluster.nodes.clone();
    cluster
        .run(async move {
            timeout(Duration::from_secs(180), async {
                ready(&nodes).await;
                answering(&nodes);
                let id = source(&nodes[0], &["original@example.org"]).await;
                let address = "other@example.org";
                let other = source(&nodes[0], &[address]).await;
                let mut report = inbound(
                    id,
                    ReportKind::Bounce,
                    vec![block(address, (5, 1, 1), "gone")],
                );
                report.recipient = crypto::ANY;
                assert_eq!(nodes[1].report(report).await, Ok(ReportOutcome::Unmatched));
                assert_eq!(
                    reports(&nodes[0], id, EventKind::Bounced).await,
                    [] as [sched::EventRead; 0]
                );
                assert_eq!(
                    reports(&nodes[0], other, EventKind::Bounced).await,
                    [] as [sched::EventRead; 0]
                );
                assert_eq!(
                    nodes[0].suppressions().get(1, address).await.expect("get"),
                    None
                );
            })
            .await
        })
        .expect("report test timed out");
    cluster.stop();
}

#[test]
fn complaints_replace_only_bounce_entries() {
    let (_, cluster) = setup(160);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let address = "complaint@example.org";
        let first = source(&nodes[0], &[address]).await;
        let second = source(&nodes[0], &[address]).await;
        let lists = nodes[0].suppressions();
        lists
            .add(1, address, Reason::Bounce, None)
            .await
            .expect("bounce");
        let report = |message| {
            inbound(
                message,
                ReportKind::Complaint,
                vec![block(address, (0, 0, 0), "")],
            )
        };
        assert_eq!(
            nodes[0].report(report(first)).await,
            Ok(ReportOutcome::Written(1))
        );
        assert_eq!(
            lists.get(1, address).await.expect("get").map(|s| s.reason),
            Some(Reason::Complaint)
        );
        lists
            .add(1, address, Reason::Unsubscribe, None)
            .await
            .expect("unsubscribe");
        assert_eq!(
            nodes[0].report(report(second)).await,
            Ok(ReportOutcome::Written(1))
        );
        assert_eq!(
            lists.get(1, address).await.expect("get").map(|s| s.reason),
            Some(Reason::Unsubscribe)
        );
        assert_eq!(
            reports(&nodes[0], first, EventKind::Complained).await.len(),
            1
        );
        assert_eq!(
            reports(&nodes[0], second, EventKind::Complained)
                .await
                .len(),
            1
        );
    });
    cluster.stop();
}

#[test]
fn another_tenant_with_the_same_message_id_is_unmatched() {
    let (_, cluster) = setup(170);
    let nodes = cluster.nodes.clone();
    cluster.run(async move {
        ready(&nodes).await;
        answering(&nodes);
        let id = source(&nodes[0], &["tenant@example.org"]).await;
        let mut report = inbound(
            id,
            ReportKind::Bounce,
            vec![block("tenant@example.org", (5, 1, 1), "gone")],
        );
        report.tenant = 2;
        assert_eq!(nodes[1].report(report).await, Ok(ReportOutcome::Unmatched));
        assert_eq!(reports(&nodes[0], id, EventKind::Bounced).await.len(), 0);
    });
    cluster.stop();
}
