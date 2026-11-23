use std::rc::Rc;

use rt::sim::{Config, Disk, SimDriver};
use rt::{JoinHandle, Runtime, spawn};
use spool::{
    Body, Done, Error, Event, Head, HeadClear, Limits, Message, MessageId, Outcome, Recipient,
    Reply, Report, Slice, Spool, Stamp, StateClear, Status, state_item,
};
use store::{
    Change, Claim, Client, DataFile, Delivery, Index, IndexRecord, IndexStamp, Keeper, Key,
    MAX_PAYLOAD, Options, SLOT_SIZE, Setup, Tiering, boot, control_key,
};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 32,
    shards: 2,
};

const LIMITS: Limits = Limits {
    recipients: 1000,
    inline: 1024,
    body: 64 * 1024,
    read: 1024 * 1024,
};

struct Node {
    spool: Spool,
    owner: JoinHandle<Keeper>,
    committer: JoinHandle<()>,
    client: Client,
}

impl Node {
    async fn open() -> Self {
        Self::open_with(None).await
    }

    async fn open_with(tiering: Option<Tiering>) -> Self {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
            flush: 0,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(async move { drop(booted.committer.run().await) });
        let mut core = booted
            .starts
            .into_iter()
            .next()
            .expect("core")
            .open()
            .await
            .expect("open");
        if let Some(tiering) = tiering {
            core.keeper.set_tiering(tiering);
        }
        let (spool, owner) = Spool::new(core, 1, LIMITS).expect("limits");
        Self {
            spool,
            owner: spawn(owner.run()),
            committer,
            client: booted.client,
        }
    }

    async fn close(self) -> Keeper {
        self.spool.changes().close();
        let keeper = self.owner.await;
        drop(self.spool);
        drop(self.client);
        self.committer.await;
        keeper
    }

    async fn accept(&self, shard: u16, recipients: usize, expiry: u64) -> MessageId {
        let id = self.spool.id(shard).await.expect("id");
        let message = Message {
            id,
            tenant: 7,
            head: Head {
                clear: HeadClear {
                    recipients: u32::try_from(recipients).expect("fits"),
                    accepted: 10,
                    not_before: 20,
                    ..HeadClear::default()
                },
                expiry,
                wrap: [3; spool::WRAP],
                sealed: vec![1; 50],
            },
            body: Body::Inline(vec![3; 10]),
            slices: vec![Slice {
                queues: vec![4; recipients],
                sealed: vec![2; recipients],
            }],
        };
        self.spool.accept(vec![message]).await.expect("accept");
        id
    }
}

fn created() -> Disk {
    let setup = Rc::new(SimDriver::new(1, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

fn on<F>(disk: Disk, work: impl FnOnce() -> F) -> (F::Output, Disk)
where
    F: Future + 'static,
    F::Output: 'static,
{
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), disk));
    let output = Runtime::new(driver.clone()).block_on(work());
    (output, driver.crash())
}

fn deferred(recipient: u32, due: u64) -> Report {
    Report {
        recipient,
        outcome: Outcome::Deferred {
            due,
            class: 2,
            notified: true,
        },
        reply: None,
        event: None,
    }
}

fn done(recipient: u32, outcome: Outcome) -> Report {
    Report {
        recipient,
        outcome,
        reply: None,
        event: None,
    }
}

fn refused<T: std::fmt::Debug>(result: Result<T, Error>, what: &str) {
    match result {
        Err(Error::State(found)) if found == what => {}
        other => panic!("expected {what}, got {other:?}"),
    }
}

const READY: Recipient = Recipient {
    status: Status::Ready,
    attempts: 0,
    due: 20,
    class: 0,
    notified: false,
};

fn event(n: u8, stamp: Stamp) -> Event {
    Event {
        recipient: 0,
        stamp,
        record: IndexRecord {
            stamp: IndexStamp::Head,
            kind: 3,
            partition: 0,
            entry: index::Entry::put(index::key(7, [0; 16]), vec![n; 61], vec![n; 5]),
        },
        search: Vec::new(),
        carried: 0,
    }
}

fn search(n: u8) -> IndexRecord {
    let mut key = index::key(7, [0; 16]);
    key[4] = n;
    IndexRecord {
        stamp: IndexStamp::Tail,
        kind: 4,
        partition: 0,
        entry: index::Entry::put(key, vec![n; 14], Vec::new()),
    }
}

fn unit(n: u8, stamp: Stamp) -> Event {
    Event {
        search: (1..=3).map(search).collect(),
        ..event(n, stamp)
    }
}

async fn tails(spool: &Spool) -> Vec<(u64, u8)> {
    spool
        .changes()
        .scan(0, (4, 0), [0; 20]..[0xff; 20], usize::MAX)
        .await
        .expect("scan")
        .into_iter()
        .map(|e| {
            let tail = u64::from_be_bytes(e.key[12..20].try_into().expect("tail"));
            (u64::MAX - tail, e.key[4])
        })
        .collect()
}

#[test]
fn event_units_are_written_and_dropped_whole_and_counted_by_cause() {
    on(created(), || async {
        let node = Node::open_with(Some(Tiering {
            flush_size: 0,
            fan_in: 64,
            ..Tiering::default()
        }))
        .await;
        let spool = &node.spool;
        let id = node.accept(0, 4, 500).await;
        let report = |n: u8, event: Event| Report {
            event: Some(event),
            ..deferred(0, 50 + u64::from(n))
        };
        spool.claim(id, 0).expect("claim");
        let first = report(1, unit(1, spool.stamp(0).expect("stamp")));
        assert_eq!(
            spool.report(id, vec![first]).await.expect("report"),
            Done::Kept
        );
        let written = events(spool).await;
        let mut found = tails(spool).await;
        found.sort_unstable();
        assert_eq!(written.len(), 1);
        assert_eq!(
            found,
            (1..=3u8)
                .map(|n| (written[0].0 + u64::from(n), n))
                .collect::<Vec<_>>()
        );
        assert_eq!(spool.event_stats(), spool::EventStats::default());
        node.client.checkpoint().await.expect("checkpoint");
        for n in 0..=store::DELAY_RUNS {
            let mut filler = search(9);
            filler.entry.key[5] = u8::try_from(n).expect("few runs");
            spool
                .changes()
                .index(0, Claim::Control, vec![filler])
                .await
                .expect("index");
            node.client.checkpoint().await.expect("checkpoint");
        }
        spool.claim(id, 0).expect("claim");
        let busy = report(2, unit(2, spool.stamp(0).expect("stamp")));
        assert_eq!(
            spool.report(id, vec![busy]).await.expect("report"),
            Done::Kept
        );
        assert_eq!(events(spool).await.len(), 1);
        let own = tails(spool).await.into_iter().filter(|t| t.1 != 9).count();
        assert_eq!(own, 3);
        spool.claim(id, 0).expect("claim");
        let alone = report(3, event(3, spool.stamp(0).expect("stamp")));
        assert_eq!(
            spool.report(id, vec![alone]).await.expect("report"),
            Done::Kept
        );
        assert_eq!(events(spool).await.len(), 2);
        spool.claim(id, 0).expect("claim");
        let mut wide = unit(4, spool.stamp(0).expect("stamp"));
        wide.search[2].entry.value.push(0);
        let refused = report(4, wide);
        assert_eq!(
            spool.report(id, vec![refused]).await.expect("report"),
            Done::Kept
        );
        assert_eq!(events(spool).await.len(), 2);
        assert_eq!(
            spool.event_stats(),
            spool::EventStats {
                lost: 2,
                busy_event: 0,
                busy_search: 1,
                refused: 1,
                search_skipped: 1,
            }
        );
        assert_eq!(spool.take_lost(7), 2);
        node.close().await;
    });
}

async fn events(spool: &Spool) -> Vec<(u64, u8)> {
    spool
        .changes()
        .scan(0, (3, 0), [0; 20]..[0xff; 20], usize::MAX)
        .await
        .expect("scan")
        .into_iter()
        .map(|e| {
            let stamp = u64::from_be_bytes(e.key[4..12].try_into().expect("stamp"));
            (stamp, e.value[0])
        })
        .collect()
}

#[test]
fn events_commit_with_their_reports_and_the_drop() {
    let (seen, disk) = on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 2, 500).await;
        spool.claim(id, 0).expect("claim");
        let first = Report {
            event: Some(event(1, spool.stamp(0).expect("stamp"))),
            ..deferred(0, 50)
        };
        assert_eq!(
            spool.report(id, vec![first]).await.expect("report"),
            Done::Kept
        );
        spool.claim(id, 0).expect("claim");
        spool.claim(id, 1).expect("claim");
        let last = vec![
            Report {
                event: Some(event(2, spool.stamp(0).expect("stamp"))),
                ..done(0, Outcome::Delivered)
            },
            Report {
                event: Some(event(3, spool.stamp(0).expect("stamp"))),
                ..done(1, Outcome::Failed)
            },
        ];
        assert_eq!(spool.report(id, last).await.expect("report"), Done::Dropped);
        let seen = events(spool).await;
        assert_eq!(seen.iter().map(|e| e.1).collect::<Vec<_>>(), [1, 2, 3]);
        assert!(seen.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!((spool.take_lost(7), spool.lost_events()), (0, 0));
        node.close().await;
        seen
    });
    on(disk, || async move {
        let node = Node::open().await;
        assert_eq!(events(&node.spool).await, seen);
        node.close().await;
    });
}

#[test]
fn refused_events_are_counted_as_lost_with_what_they_carried() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 2, 500).await;
        spool.claim(id, 0).expect("claim");
        let first = Report {
            event: Some(event(1, spool.stamp(0).expect("stamp"))),
            ..deferred(0, 50)
        };
        spool.report(id, vec![first]).await.expect("report");
        spool.claim(id, 0).expect("claim");
        let mut wide = event(2, spool.stamp(0).expect("stamp"));
        wide.record.entry.value.push(0);
        wide.carried = 4;
        let shaped = Report {
            event: Some(wide),
            ..deferred(0, 60)
        };
        assert_eq!(
            spool.report(id, vec![shaped]).await.expect("plain"),
            Done::Kept
        );
        assert_eq!(spool.lost_events(), 5);
        assert_eq!(spool.take_lost(7), 5);
        assert_eq!(spool.take_lost(7), 0);
        assert_eq!(events(spool).await.len(), 1);
        let mut unclaimed = event(3, spool.stamp(0).expect("stamp"));
        unclaimed.carried = 2;
        let early = Report {
            event: Some(unclaimed),
            ..deferred(1, 70)
        };
        refused(spool.report(id, vec![early]).await, "not claimed");
        assert_eq!(spool.take_lost(7), 3);
        spool.claim(id, 1).expect("claim");
        let ahead = Stamp {
            write: spool.stamp(0).expect("stamp").write + 5,
            ..spool.stamp(0).expect("stamp")
        };
        let future = Report {
            event: Some(event(4, ahead)),
            ..deferred(1, 70)
        };
        refused(spool.report(id, vec![future]).await, "stamp");
        assert_eq!(spool.take_lost(7), 1);
        assert_eq!(spool.lost_events(), 9);
        node.close().await;
    });
}

#[test]
fn reports_need_a_claim_and_a_valid_reply() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 4, 500).await;
        assert_eq!(spool.recipient(id, 4), None);
        refused(spool.claim(id, 4), "recipient");
        assert_eq!(spool.claim(id, 0).expect("claim"), READY);
        refused(spool.claim(id, 0), "claimed");
        refused(spool.report(id, vec![deferred(1, 5)]).await, "not claimed");
        refused(
            spool.report(id, vec![deferred(0, 5), deferred(0, 6)]).await,
            "not claimed",
        );
        let early = Report {
            reply: Some(Reply {
                stamp: Stamp { boot: 1, write: 0 },
                sealed: vec![9; 20],
            }),
            ..deferred(0, 5)
        };
        refused(spool.report(id, vec![early]).await, "stamp");
        let large = Report {
            reply: Some(Reply {
                stamp: spool.stamp(0).expect("stamp"),
                sealed: vec![9; MAX_PAYLOAD],
            }),
            ..deferred(0, 5)
        };
        assert!(matches!(
            spool.report(id, vec![large]).await,
            Err(Error::Limit("report"))
        ));
        assert_eq!(spool.recipient(id, 0), Some(READY));
        node.close().await;
    });
}

#[test]
fn recipients_start_ready_and_take_their_reports() {
    let (_, disk) = on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 4, 500).await;
        assert_eq!(spool.recipient(id, 0), Some(READY));
        spool.claim(id, 0).expect("claim");
        spool.claim(id, 1).expect("claim");
        let stamp = spool.stamp(0).expect("stamp");
        let replied = Report {
            reply: Some(Reply {
                stamp,
                sealed: vec![9; 20],
            }),
            ..deferred(0, 50)
        };
        let first = {
            let spool = spool.clone();
            spawn(async move { spool.report(id, vec![replied]).await })
        };
        let second = {
            let spool = spool.clone();
            spawn(async move { spool.report(id, vec![done(1, Outcome::Delivered)]).await })
        };
        assert_eq!(first.await.expect("first"), Done::Kept);
        assert_eq!(second.await.expect("second"), Done::Kept);
        assert_eq!(
            spool.recipient(id, 0),
            Some(Recipient {
                status: Status::Deferred,
                attempts: 1,
                due: 50,
                class: 2,
                notified: true,
            })
        );
        refused(spool.claim(id, 1), "final");
        spool.claim(id, 0).expect("claim again");
        let pending = {
            let spool = spool.clone();
            spawn(async move { spool.report(id, vec![deferred(0, 80)]).await })
        };
        rt::yield_now().await;
        refused(spool.report(id, vec![deferred(0, 81)]).await, "not claimed");
        assert_eq!(pending.await.expect("deferred again"), Done::Kept);
        assert_eq!(spool.recipient(id, 0).expect("state").attempts, 2);
        let keeper = node.close().await;
        let state = keeper.state(0).expect("kept");
        let item = state.get(Key::new(id.key, state_item(0))).expect("state");
        assert_eq!((item.delivery.status, item.delivery.due), (1, 80));
        assert_eq!(
            StateClear::decode(&item.clear),
            Some(StateClear {
                class: 2,
                notified: true,
                stamp: Stamp::default(),
            })
        );
        assert_eq!(state.message(id.key).count(), 3 + 2);
        id
    });
    on(disk, || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = spool.messages()[0];
        assert_eq!(spool.recipient(id, 0).expect("state").attempts, 2);
        assert_eq!(
            spool.recipient(id, 1).expect("state").status,
            Status::Delivered
        );
        assert_eq!(spool.recipient(id, 2), Some(READY));
        refused(spool.claim(id, 1), "final");
        for r in [0, 2, 3] {
            spool.claim(id, r).expect("claim");
        }
        let last = vec![
            done(0, Outcome::Failed),
            done(2, Outcome::Delivered),
            done(3, Outcome::Delivered),
        ];
        assert_eq!(spool.report(id, last).await.expect("last"), Done::Dropped);
        assert_eq!(spool.messages(), []);
        node.close().await;
    });
}

#[test]
fn the_last_final_recipient_drops_the_message() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(1, 3, 500).await;
        let other = node.accept(1, 1, 500).await;
        for r in 0..3 {
            spool.claim(id, r).expect("claim");
        }
        spool
            .report(id, vec![done(0, Outcome::Failed)])
            .await
            .expect("failed");
        let calls = [
            vec![done(1, Outcome::Delivered)],
            vec![done(2, Outcome::Delivered)],
        ];
        let tasks: Vec<_> = calls
            .into_iter()
            .map(|reports| {
                let spool = spool.clone();
                spawn(async move { spool.report(id, reports).await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.expect("report"), Done::Dropped);
        }
        assert_eq!(spool.recipient(id, 0), None);
        refused(spool.claim(id, 0), "message");
        assert_eq!(spool.messages(), vec![other]);
        let keeper = node.close().await;
        let state = keeper.state(1).expect("kept");
        assert_eq!(state.message(id.key).count(), 0);
        assert_eq!(state.message(other.key).count(), 3);
    });
}

#[test]
fn cancel_and_expiry_wait_for_open_claims() {
    let (kept, disk) = on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let idle = node.accept(0, 2, 500).await;
        let busy = node.accept(0, 3, 500).await;
        let old = node.accept(1, 2, 100).await;
        let kept = node.accept(1, 2, 900).await;
        spool.cancel(idle).await.expect("cancel idle");
        refused(spool.claim(idle, 0), "message");
        spool.claim(busy, 0).expect("claim");
        spool.claim(busy, 2).expect("claim");
        let cancel = {
            let spool = spool.clone();
            spawn(async move { spool.cancel(busy).await })
        };
        rt::sleep(std::time::Duration::from_millis(5)).await;
        refused(spool.claim(busy, 1), "ending");
        assert!(spool.recipient(busy, 0).is_some());
        assert_eq!(
            spool
                .report(busy, vec![deferred(0, 9)])
                .await
                .expect("late"),
            Done::Kept
        );
        assert!(spool.recipient(busy, 2).is_some());
        assert_eq!(
            spool
                .report(busy, vec![done(2, Outcome::Delivered)])
                .await
                .expect("last"),
            Done::Dropped
        );
        cancel.await.expect("cancel busy");
        assert_eq!(spool.expired(150), vec![old]);
        refused(spool.expire(kept, 150).await, "not expired");
        spool.expire(old, 150).await.expect("expire");
        assert_eq!(spool.expired(150), []);
        assert_eq!(spool.messages(), vec![kept]);
        let keeper = node.close().await;
        for (shard, id) in [(0, idle), (0, busy), (1, old)] {
            let state = keeper.state(shard).expect("kept");
            assert_eq!(state.message(id.key).count(), 0);
        }
        kept
    });
    on(disk, move || async move {
        let node = Node::open().await;
        assert_eq!(node.spool.messages(), vec![kept]);
        node.close().await;
    });
}

#[test]
fn expiry_events_commit_with_the_drop_for_open_recipients_only() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 3, 100).await;
        spool.claim(id, 0).expect("claim");
        let first = spool.report(id, vec![done(0, Outcome::Delivered)]).await;
        assert_eq!(first.expect("report"), Done::Kept);
        let open: Vec<u32> = spool.open_recipients(id).iter().map(|o| o.0).collect();
        assert_eq!(open, [1, 2]);
        assert_eq!(spool.tenant(id), Some(7));
        spool.claim(id, 1).expect("claim");
        let closing: Vec<Event> = (0..3u8)
            .map(|r| Event {
                recipient: u32::from(r),
                ..event(10 + r, spool.stamp(0).expect("stamp"))
            })
            .collect();
        let expiry = {
            let spool = spool.clone();
            spawn(async move { spool.expire_with(id, 150, closing).await })
        };
        rt::sleep(std::time::Duration::from_millis(5)).await;
        let last = spool.report(id, vec![done(1, Outcome::Failed)]).await;
        assert_eq!(last.expect("report"), Done::Dropped);
        expiry.await.expect("expire");
        let values: Vec<u8> = events(spool).await.into_iter().map(|e| e.1).collect();
        assert_eq!(values, [12]);
        assert_eq!(spool.lost_events(), 0);
        assert_eq!(spool.tenant(id), None);
        node.close().await;
    });
}

#[test]
fn units_in_one_commit_keep_each_search_record_next_to_its_event() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 3, 500).await;
        for r in 0..3 {
            spool.claim(id, r).expect("claim");
        }
        let reports: Vec<Report> = (0..3u8)
            .map(|r| Report {
                event: Some(unit(20 + r, spool.stamp(0).expect("stamp"))),
                ..deferred(u32::from(r), 60)
            })
            .collect();
        assert_eq!(spool.report(id, reports).await.expect("report"), Done::Kept);
        let written = events(spool).await;
        let found = tails(spool).await;
        assert_eq!((written.len(), found.len()), (3, 9));
        for (sequence, back) in found {
            let event = sequence - u64::from(back);
            assert!(written.iter().any(|e| e.0 == event), "{sequence} {back}");
        }
        let starts: Vec<u64> = written.iter().map(|e| e.0).collect();
        assert!(starts.windows(2).all(|w| w[1] - w[0] == 4), "{starts:?}");
        node.close().await;
    });
}

#[test]
fn closing_units_past_the_region_are_lost_and_the_rest_written() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 40, 100).await;
        let closing: Vec<Event> = (0..40u8)
            .map(|r| {
                let mut unit = unit(r, spool.stamp(0).expect("stamp"));
                unit.recipient = u32::from(r);
                unit.record.entry.payload = vec![r; 4000];
                unit
            })
            .collect();
        spool.expire_with(id, 150, closing).await.expect("expire");
        let written = events(spool).await.len();
        assert!(written > 0 && written < 40, "{written}");
        assert_eq!(tails(spool).await.len(), 3 * written);
        let stats = spool.event_stats();
        assert_eq!((stats.lost, stats.refused), (40 - written as u64, 0));
        assert_eq!(spool.tenant(id), None);
        node.close().await;
    });
}

#[test]
fn released_claims_let_a_cancel_finish_and_no_claim_slips_into_its_drop() {
    let ((), disk) = on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let released = node.accept(0, 3, 500).await;
        spool.claim(released, 0).expect("claim");
        spool.claim(released, 1).expect("claim");
        let cancel = {
            let spool = spool.clone();
            spawn(async move { spool.cancel(released).await })
        };
        rt::sleep(std::time::Duration::from_millis(5)).await;
        spool.release(released, &[0, 1]);
        cancel.await.expect("cancel after release");
        refused(spool.claim(released, 2), "message");
        let busy = node.accept(1, 3, 500).await;
        spool.claim(busy, 0).expect("claim");
        let cancel = {
            let spool = spool.clone();
            spawn(async move { spool.cancel(busy).await })
        };
        rt::sleep(std::time::Duration::from_millis(5)).await;
        let report = {
            let spool = spool.clone();
            spawn(async move { spool.report(busy, vec![deferred(0, 9)]).await })
        };
        for _ in 0..3 {
            rt::yield_now().await;
        }
        refused(spool.claim(busy, 1), "ending");
        assert_eq!(report.await.expect("report"), Done::Dropped);
        cancel.await.expect("cancel busy");
        node.close().await;
    });
    on(disk, || async {
        let node = Node::open().await;
        assert_eq!(node.spool.messages(), vec![]);
        node.close().await;
    });
}

#[test]
fn reports_larger_than_a_region_are_split_into_several_merges() {
    on(created(), || async {
        let node = Node::open().await;
        let spool = &node.spool;
        let id = node.accept(0, 400, 500).await;
        let tasks: Vec<_> = (0..300)
            .map(|r| {
                spool.claim(id, r).expect("claim");
                let reply = Reply {
                    stamp: spool.stamp(0).expect("stamp"),
                    sealed: vec![8; 1000],
                };
                let report = Report {
                    reply: Some(reply),
                    ..deferred(r, 60)
                };
                let spool = spool.clone();
                spawn(async move { spool.report(id, vec![report]).await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.expect("report"), Done::Kept);
        }
        for r in 0..300 {
            assert_eq!(spool.recipient(id, r).expect("state").attempts, 1);
        }
        node.close().await;
    });
}

#[test]
fn control_items_are_not_messages_at_start() {
    let (id, disk) = on(created(), || async {
        let node = Node::open().await;
        let id = node.accept(0, 2, 500).await;
        let control = Index {
            key: Key::head(control_key(1, 3)),
            tenant: 7,
            change: Change::Put(Delivery {
                status: 0,
                attempts: 0,
                due: 0,
            }),
        };
        node.spool
            .changes()
            .change(0, control, vec![4; 30])
            .await
            .expect("control item");
        node.close().await;
        id
    });
    on(disk, || async move {
        let node = Node::open().await;
        assert_eq!(node.spool.messages(), vec![id]);
        node.close().await;
    });
}
