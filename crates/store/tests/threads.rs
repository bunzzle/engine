#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};
use std::{fs, process};

use rt::{Native, Runtime, spawn};
use store::{
    Change, Claim, Core, DataFile, Delivery, Error, Event, Index, KIND_STATE, Key, Location,
    Options, Owner, SLOT_SIZE, Setup, Submission, Write, launch,
};

const OPTIONS: Options = Options {
    journal_size: 16 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

const SETUP: Setup = Setup {
    cores: 3,
    credits: 4,
    reserve: 0,
};

struct Nobody;

impl Owner for Nobody {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        std::future::ready(None)
    }
}

#[derive(Default)]
struct Seen {
    threads: BTreeMap<u16, ThreadId>,
    shards: BTreeMap<u16, Vec<u16>>,
    keys: BTreeMap<u16, Vec<u64>>,
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("store-{name}-{}", process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("store");
    let _ = fs::remove_file(&path);
    let target = path.clone();
    Runtime::new(Rc::new(Native::new().expect("native driver"))).block_on(async move {
        DataFile::create(&target, &OPTIONS).await.expect("create");
    });
    path
}

fn put(key: u64) -> Index {
    Index {
        key: Key::head(key),
        tenant: 5,
        change: Change::Put(Delivery {
            status: 1,
            attempts: 0,
            due: key,
        }),
    }
}

async fn fill(mut core: Core) {
    let mut sent = BTreeMap::new();
    for (tag, &shard) in (0u64..).zip(&core.shards) {
        let index = put(u64::from(shard) * 100 + u64::from(core.index));
        let submission = Submission {
            claim: Claim::Intake,
            records: vec![Write {
                kind: KIND_STATE,
                counted: true,
                shard,
                tenant: 5,
                payload: index.payload(&[9; 40]),
            }],
            bodies: Vec::new(),
            dead: Vec::new(),
        };
        core.session.submit(tag, submission).expect("credit");
        sent.insert(tag, (shard, index));
    }
    let mut written = Vec::new();
    while !sent.is_empty() {
        match core.results.recv().await.expect("event") {
            Event::Durable {
                tag,
                sequence,
                locations,
            } => {
                let (shard, index) = sent.remove(&tag).expect("sent");
                core.keeper
                    .apply(shard, &index, &[], &[], locations[0], sequence);
                written.push(locations[0]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    let reader = core.file.reader();
    for location in written {
        let buf = reader.read(location, 5, &Nobody).await.expect("read");
        assert_eq!(buf.len(), location.size as usize);
    }
    let checkpoint = (core.index == 0).then(|| {
        let client = core.session.client().clone();
        spawn(async move { client.checkpoint().await })
    });
    loop {
        match core.results.recv().await.expect("event") {
            Event::Cut { sequence } => core
                .keeper
                .cut(&core.session, &core.file, sequence)
                .await
                .expect("cut"),
            Event::Published { sequence } => {
                core.keeper.published(sequence);
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    if let Some(checkpoint) = checkpoint {
        checkpoint.await.expect("checkpoint");
    }
}

fn record(seen: &Arc<Mutex<Seen>>, core: &Core) {
    let mut seen = seen.lock().expect("lock");
    seen.threads.insert(core.index, thread::current().id());
    seen.shards.insert(core.index, core.shards.clone());
    let keys = core
        .shards
        .iter()
        .flat_map(|&s| {
            core.keeper
                .state(s)
                .expect("kept")
                .entries()
                .keys()
                .map(|k| k.message)
        })
        .collect();
    seen.keys.insert(core.index, keys);
}

#[test]
fn cores_run_on_their_own_threads_and_rebuild_their_shards() {
    let path = scratch("threads");
    let first = Arc::new(Mutex::new(Seen::default()));
    let seen = Arc::clone(&first);
    let committer = launch(&path, SETUP, move |core| {
        record(&seen, &core);
        fill(core)
    })
    .expect("launch");
    assert!(!committer.is_failed());
    drop(committer);
    let first = first.lock().expect("lock");
    let threads: Vec<ThreadId> = first.threads.values().copied().collect();
    assert_eq!(threads.len(), 3);
    assert!(threads.iter().all(|&t| t != thread::current().id()));
    assert!(threads.windows(2).all(|w| w[0] != w[1]));
    assert_eq!(first.shards[&0], vec![0, 3]);
    assert_eq!(first.shards[&1], vec![1]);
    assert_eq!(first.shards[&2], vec![2]);
    assert!(first.keys.values().all(Vec::is_empty));

    let second = Arc::new(Mutex::new(Seen::default()));
    let seen = Arc::clone(&second);
    let setup = Setup { cores: 2, ..SETUP };
    launch(&path, setup, move |core| {
        record(&seen, &core);
        async {}
    })
    .expect("relaunch");
    let second = second.lock().expect("lock");
    assert_eq!(second.keys[&0], vec![0, 202]);
    assert_eq!(second.keys[&1], vec![101, 300]);
    fs::remove_dir_all(path.parent().expect("dir")).expect("clean up");
}

#[test]
fn a_bad_core_count_is_refused_before_any_thread_starts() {
    let path = scratch("cores");
    for cores in [0, 5] {
        let result = launch(&path, Setup { cores, ..SETUP }, |_| async {});
        assert!(matches!(result, Err(Error::Config(_))));
    }
    fs::remove_dir_all(path.parent().expect("dir")).expect("clean up");
}
