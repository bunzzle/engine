use std::rc::Rc;

use rt::sim::{Config, Disk, SimDriver};
use rt::{JoinHandle, Runtime, spawn};
use spool::{
    Body, Done, Error, Head, HeadClear, Limits, Message, MessageId, Outcome, Recipient, Reply,
    Report, Slice, Spool, Stamp, StateClear, Status, state_item,
};
use store::{Client, DataFile, Keeper, MAX_PAYLOAD, Options, SLOT_SIZE, Setup, boot};

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
};

struct Node {
    spool: Spool,
    owner: JoinHandle<Keeper>,
    committer: JoinHandle<()>,
    client: Client,
}

impl Node {
    async fn open() -> Self {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(async move { drop(booted.committer.run().await) });
        let core = booted
            .starts
            .into_iter()
            .next()
            .expect("core")
            .open()
            .await
            .expect("open");
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
    }
}

fn done(recipient: u32, outcome: Outcome) -> Report {
    Report {
        recipient,
        outcome,
        reply: None,
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
        let item = state
            .get(store::Key::new(id.key, state_item(0)))
            .expect("state");
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
