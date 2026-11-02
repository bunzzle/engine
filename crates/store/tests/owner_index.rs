use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use index::{Entry, Op, Shape};
use rt::sim::{Config, SimDriver};
use rt::{Runtime, now, spawn};
use store::{
    Changes, Claim, Client, Committer, DataFile, Error, IndexRecord, Keeper, Options, SLOT_SIZE,
    Setup, Shards, Tiering, boot,
};

const PATH: &str = "/data/owner";
const SHAPE: Shape = Shape { value: 8 };
const KIND: u8 = 1;
const PARTITION: (u8, u32) = (KIND, 0);

const OPTIONS: Options = Options {
    journal_size: 8 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 64,
    shards: 2,
};

type Model = BTreeMap<[u8; 20], (Op, Vec<u8>, Vec<u8>)>;

struct Node {
    client: Client,
    changes: Changes,
    owner: rt::JoinHandle<Keeper>,
    committer: rt::JoinHandle<Committer>,
}

impl Node {
    async fn stop(self) -> Keeper {
        self.changes.close();
        let keeper = self.owner.await;
        drop(self.client);
        drop(self.committer.await);
        keeper
    }
}

fn created(seed: u64) -> rt::sim::Disk {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    setup.crash()
}

async fn open(tiering: Option<Tiering>) -> Node {
    let setup = Setup {
        cores: 1,
        credits: 8,
        reserve: 0,
        flush: 2,
    };
    let booted = boot(PATH, setup).await.expect("boot");
    let committer = spawn(booted.committer.run());
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
    let (owner, changes) = Shards::new(core);
    Node {
        client: booted.client,
        changes,
        owner: spawn(owner.run()),
        committer,
    }
}

fn key(n: u64) -> [u8; 20] {
    let mut hash = [0; 16];
    hash[..8].copy_from_slice(&n.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    hash[8..].copy_from_slice(&n.to_le_bytes());
    index::key(u32::try_from(n % 3).expect("fits") + 1, hash)
}

fn put(n: u64, round: u64) -> IndexRecord {
    let payload =
        vec![u8::try_from(n % 251).expect("fits"); usize::try_from(n % 30).expect("fits")];
    IndexRecord {
        kind: KIND,
        partition: 0,
        entry: Entry::put(key(n), (n ^ round).to_le_bytes().to_vec(), payload),
    }
}

fn delete(n: u64) -> IndexRecord {
    IndexRecord {
        kind: KIND,
        partition: 0,
        entry: Entry::delete(key(n), SHAPE),
    }
}

fn remember(model: &mut Model, record: &IndexRecord) {
    let entry = &record.entry;
    model.insert(
        entry.key,
        (entry.op, entry.value.clone(), entry.payload.clone()),
    );
}

async fn check(changes: &Changes, model: &Model, keys: u64) {
    let asked: Vec<(u16, [u8; 20])> = (0..keys).map(|n| (0, key(n))).collect();
    let found = changes.lookup(PARTITION, asked).await.expect("lookup");
    for (n, found) in (0..keys).zip(found) {
        let expected = model
            .get(&key(n))
            .filter(|(op, _, _)| *op == Op::Put)
            .map(|(op, value, _)| (*op, value.clone()));
        let found = found.filter(|(op, _)| *op == Op::Put);
        assert_eq!(found, expected, "key {n}");
    }
    let all = changes
        .scan(0, PARTITION, [0; 20]..[0xff; 20], usize::MAX)
        .await
        .expect("scan");
    let listed: Model = all
        .into_iter()
        .filter(|e| e.op == Op::Put)
        .map(|e| (e.key, (e.op, e.value, e.payload)))
        .collect();
    let live: Model = model
        .iter()
        .filter(|(_, (op, _, _))| *op == Op::Put)
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    assert_eq!(listed, live);
}

#[test]
fn index_writes_answer_after_apply_and_survive_restart() {
    let driver = Rc::new(SimDriver::with_disk(1, Config::default(), created(1)));
    let disk = Runtime::new(driver.clone()).block_on(async {
        let node = open(None).await;
        let mut model = Model::new();
        for n in 0..40 {
            let record = put(n, 1);
            node.changes
                .index(0, Claim::Control, vec![record.clone()])
                .await
                .expect("put");
            remember(&mut model, &record);
            let found = node
                .changes
                .lookup(PARTITION, vec![(0, key(n))])
                .await
                .expect("lookup");
            assert_eq!(found, vec![Some((Op::Put, record.entry.value))]);
            if n % 10 == 9 {
                node.client.checkpoint().await.expect("checkpoint");
            }
        }
        let gone: Vec<IndexRecord> = (0..40).step_by(4).map(delete).collect();
        for record in &gone {
            remember(&mut model, record);
        }
        node.changes
            .index(0, Claim::Control, gone)
            .await
            .expect("delete");
        check(&node.changes, &model, 40).await;
        node.client.checkpoint().await.expect("checkpoint");
        let late = put(41, 2);
        node.changes
            .index(0, Claim::Control, vec![late.clone()])
            .await
            .expect("late");
        remember(&mut model, &late);
        drop(node.stop().await);
        model
    });
    let model = disk;
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), driver.crash()));
    Runtime::new(driver).block_on(async move {
        let node = open(None).await;
        check(&node.changes, &model, 42).await;
        drop(node.stop().await);
    });
}

#[test]
fn scans_take_a_key_range_and_a_limit() {
    let driver = Rc::new(SimDriver::with_disk(3, Config::default(), created(3)));
    Runtime::new(driver).block_on(async {
        let node = open(None).await;
        let mut model = Model::new();
        for n in 0..60 {
            let record = put(n, 3);
            remember(&mut model, &record);
            node.changes
                .index(0, Claim::Control, vec![record])
                .await
                .expect("put");
            if n % 25 == 24 {
                node.client.checkpoint().await.expect("checkpoint");
            }
        }
        let from = index::key(2, [0; 16]);
        let to = index::key(3, [0; 16]);
        let expected: Vec<[u8; 20]> = model.range(from..to).map(|(k, _)| *k).collect();
        assert!(expected.len() > 10);
        let mut seen = Vec::new();
        let mut at = from;
        loop {
            let page = node
                .changes
                .scan(0, PARTITION, at..to, 7)
                .await
                .expect("scan");
            assert!(page.len() <= 7);
            let Some(last) = page.last() else { break };
            let mut next = last.key;
            for byte in next.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    break;
                }
            }
            at = next;
            seen.extend(page.iter().map(|e| e.key));
        }
        assert_eq!(seen, expected);
        let missing = node
            .changes
            .scan(0, (KIND, 9), from..to, 5)
            .await
            .expect("empty");
        assert_eq!(missing, Vec::new());
        drop(node.stop().await);
    });
}

#[test]
fn index_writes_refuse_foreign_shards_and_mixed_shapes() {
    let driver = Rc::new(SimDriver::with_disk(4, Config::default(), created(4)));
    Runtime::new(driver).block_on(async {
        let node = open(None).await;
        let foreign = node.changes.index(7, Claim::Control, vec![put(1, 1)]).await;
        assert!(matches!(foreign, Err(Error::Invalid("owner"))));
        let empty = node.changes.index(0, Claim::Control, Vec::new()).await;
        assert!(matches!(empty, Err(Error::Invalid("batch"))));
        let mut wide = put(2, 1);
        wide.entry.value.push(0);
        let mixed = node
            .changes
            .index(0, Claim::Control, vec![put(1, 1), wide.clone()])
            .await;
        assert!(matches!(mixed, Err(Error::Invalid("index shape"))));
        let nothing = node
            .changes
            .lookup(PARTITION, vec![(0, key(1)), (0, key(2))])
            .await
            .expect("lookup");
        assert_eq!(nothing, vec![None, None]);
        node.changes
            .index(0, Claim::Control, vec![put(1, 1)])
            .await
            .expect("put");
        let later = node.changes.index(0, Claim::Control, vec![wide]).await;
        assert!(matches!(later, Err(Error::Invalid("index shape"))));
        let lookup = node.changes.lookup(PARTITION, vec![(5, key(1))]).await;
        assert!(matches!(lookup, Err(Error::Invalid("owner"))));
        let scan = node
            .changes
            .scan(5, PARTITION, [0; 20]..[0xff; 20], 1)
            .await;
        assert!(matches!(scan, Err(Error::Invalid("owner"))));
        let found = node
            .changes
            .lookup(PARTITION, vec![(0, key(1)), (0, key(2))])
            .await
            .expect("lookup");
        assert_eq!(found, vec![Some((Op::Put, put(1, 1).entry.value)), None]);
        drop(node.stop().await);
    });
}

#[test]
fn many_runs_delay_index_writes_then_refuse_them() {
    let driver = Rc::new(SimDriver::with_disk(5, Config::default(), created(5)));
    Runtime::new(driver).block_on(async {
        let tiering = Tiering {
            flush_size: 0,
            fan_in: 64,
            ..Tiering::default()
        };
        let node = open(Some(tiering)).await;
        for n in 0..store::REFUSE_RUNS as u64 {
            let started = now();
            let result = node.changes.index(0, Claim::Control, vec![put(n, 5)]).await;
            let waited = now().saturating_duration_since(started);
            let runs = usize::try_from(n).expect("fits");
            assert!(result.is_ok(), "write {n}: {result:?}");
            if runs > store::DELAY_RUNS {
                let steps = u32::try_from(runs - store::DELAY_RUNS).expect("fits");
                assert!(waited >= Duration::from_millis(10) * steps, "write {n}");
            } else {
                assert!(waited < Duration::from_millis(10), "write {n}: {waited:?}");
            }
            node.client.checkpoint().await.expect("checkpoint");
        }
        let refused = node
            .changes
            .index(0, Claim::Control, vec![put(99, 5)])
            .await;
        assert!(matches!(refused, Err(Error::Busy)), "{refused:?}");
        let other = IndexRecord {
            partition: 1,
            ..put(99, 5)
        };
        node.changes
            .index(0, Claim::Control, vec![other])
            .await
            .expect("other partition");
        drop(node.stop().await);
    });
}

#[test]
fn lookups_and_scans_match_a_model_while_merges_and_cuts_run() {
    for seed in 10..14 {
        let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), created(seed)));
        Runtime::new(driver.clone()).block_on(async move {
            let tiering = Tiering {
                flush_size: 1,
                fan_in: 2,
                bytes_per_tick: 16 * 1024,
                tick: Duration::from_millis(1),
                ..Tiering::default()
            };
            let node = Rc::new(open(Some(tiering)).await);
            let checkpoints = {
                let client = node.client.clone();
                spawn(async move {
                    for _ in 0..30 {
                        let _ = client.checkpoint().await;
                        rt::sleep(Duration::from_millis(3)).await;
                    }
                })
            };
            let mut model = Model::new();
            for step in 0..300u64 {
                let n = (step * 7 + seed) % 50;
                let record = if (step + seed).is_multiple_of(5) {
                    delete(n)
                } else {
                    put(n, step)
                };
                node.changes
                    .index(0, Claim::Control, vec![record.clone()])
                    .await
                    .expect("write");
                remember(&mut model, &record);
                if step % 20 == 0 {
                    check(&node.changes, &model, 50).await;
                }
                rt::sleep(Duration::from_micros(300)).await;
            }
            checkpoints.await;
            check(&node.changes, &model, 50).await;
            for _ in 0..20 {
                node.client.checkpoint().await.expect("checkpoint");
                rt::sleep(Duration::from_millis(20)).await;
                check(&node.changes, &model, 50).await;
            }
            let node = Rc::into_inner(node).expect("only owner");
            let keeper = node.stop().await;
            let runs = keeper.runs(0, PARTITION);
            assert!((1..8).contains(&runs), "seed {seed}: {runs} runs");
        });
    }
}
