use std::rc::Rc;

use rt::sim::{Config, SimDriver};
use rt::{Buf, Runtime, spawn};
use store::{
    Change, Claim, Committer, DataFile, Delivery, INDEX_SIZE, Index, Location, Options, Record,
    SLOT_SIZE, ShardState, Submission, Write, load, recover,
};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

fn location(region: u32, offset: u64) -> Location {
    Location {
        region,
        epoch: 1,
        offset,
        sequence: offset,
        size: 128,
    }
}

fn put(key: u64, status: u8) -> Index {
    Index {
        key,
        tenant: 7,
        change: Change::Put(Delivery {
            status,
            attempts: u16::from(status),
            due: 1000 + key,
        }),
    }
}

#[test]
fn index_parts_round_trip_and_reject_damage() {
    let changes = [
        put(5, 2),
        Index {
            key: 6,
            tenant: 7,
            change: Change::Delete,
        },
        Index {
            key: 7,
            tenant: 8,
            change: Change::Move {
                old: location(3, 512),
            },
        },
    ];
    for index in changes {
        let payload = index.payload(b"sealed bytes");
        assert_eq!(payload.len(), INDEX_SIZE + 12);
        assert_eq!(Index::decode(&payload), Some(index));
        assert_eq!(&payload[INDEX_SIZE..], b"sealed bytes");
    }
    let good = put(1, 1).payload(&[]);
    assert_eq!(Index::decode(&good[..INDEX_SIZE - 1]), None);
    let mut bad_op = good.clone();
    bad_op[0] = 9;
    assert_eq!(Index::decode(&bad_op), None);
    let mut reserved = good;
    reserved[INDEX_SIZE - 1] = 1;
    assert_eq!(Index::decode(&reserved), None);
}

#[test]
fn apply_puts_deletes_and_moves() {
    let mut state = ShardState::default();
    state.apply(&put(1, 1), location(1, 0), 10);
    state.apply(&put(2, 1), location(1, 128), 11);
    state.apply(&put(1, 3), location(1, 256), 12);
    assert_eq!(state.get(1).map(|e| e.delivery.status), Some(3));
    assert_eq!(state.get(1).map(|e| e.location), Some(location(1, 256)));
    let outdated = Index {
        key: 1,
        tenant: 7,
        change: Change::Move {
            old: location(1, 0),
        },
    };
    state.apply(&outdated, location(2, 0), 13);
    assert_eq!(state.get(1).map(|e| e.location), Some(location(1, 256)));
    let moved = Index {
        key: 1,
        tenant: 7,
        change: Change::Move {
            old: location(1, 256),
        },
    };
    state.apply(&moved, location(2, 128), 14);
    assert_eq!(state.get(1).map(|e| e.location), Some(location(2, 128)));
    assert_eq!(state.get(1).map(|e| e.delivery.status), Some(3));
    let delete = Index {
        key: 2,
        tenant: 7,
        change: Change::Delete,
    };
    state.apply(&delete, location(2, 256), 15);
    assert_eq!(state.get(2), None);
    assert_eq!(state.len(), 1);
    assert_eq!(state.covered(), 15);
}

#[test]
fn frozen_deltas_are_copies_and_restore_under_newer_changes() {
    let mut state = ShardState::default();
    state.apply(&put(1, 1), location(1, 0), 1);
    state.apply(&put(2, 1), location(1, 128), 2);
    let frozen = state.freeze(2);
    assert_eq!(frozen.covered, 2);
    assert_eq!(frozen.changes.len(), 2);
    state.apply(&put(1, 5), location(1, 256), 3);
    let delete = Index {
        key: 2,
        tenant: 7,
        change: Change::Delete,
    };
    state.apply(&delete, location(1, 384), 4);
    assert_eq!(
        frozen.changes[&1].map(|e| e.delivery.status),
        Some(1),
        "a frozen delta keeps its values"
    );
    state.restore(frozen);
    let merged = state.freeze(4);
    assert_eq!(merged.changes[&1].map(|e| e.delivery.status), Some(5));
    assert_eq!(merged.changes[&2], None);
    assert_eq!(merged.covered, 4);
}

#[test]
fn applying_results_and_records_read_back_give_the_same_map() {
    let setup = Rc::new(SimDriver::new(11, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(11, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(async {
        let data = DataFile::open(PATH).await.expect("open");
        let loaded = load(&data, 0).await.expect("load");
        let recovered = recover(&data, loaded.position, loaded.state)
            .await
            .expect("recover");
        let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
        let committer = spawn(committer.run());
        let mut live = ShardState::default();
        let mut written = Vec::new();
        for step in 0..60u64 {
            let key = step % 9;
            let index = match step % 5 {
                3 => live.get(key).map_or(put(key, 1), |entry| Index {
                    key,
                    tenant: 7,
                    change: Change::Move {
                        old: entry.location,
                    },
                }),
                4 => Index {
                    key,
                    tenant: 7,
                    change: Change::Delete,
                },
                _ => put(key, u8::try_from(step % 200).expect("fits")),
            };
            let submission = Submission {
                claim: Claim::Intake,
                records: vec![Write {
                    kind: 9,
                    counted: true,
                    shard: 1,
                    tenant: 7,
                    payload: index.payload(&[0xAB; 40]),
                }],
                bodies: Vec::new(),
                dead: Vec::new(),
            };
            let durable = client.commit(submission).await.expect("commit");
            live.apply(&index, durable.locations[0], durable.sequence);
            written.push((durable.sequence, durable.locations[0]));
        }
        drop(client);
        let committer = committer.await;
        let mut replayed = ShardState::default();
        for (sequence, location) in written {
            let offset = committer.data().region_offset(location.region) + location.offset;
            let (read, buf) = committer
                .data()
                .file()
                .read_at(Buf::new(location.size as usize), offset)
                .await;
            read.expect("read");
            let record = Record::decode(&buf).expect("record");
            assert_eq!(record.shard(), 1);
            let index = Index::decode(record.payload()).expect("index part");
            replayed.apply(&index, location, sequence);
        }
        assert_eq!(replayed.entries(), live.entries());
        assert_eq!(replayed.covered(), live.covered());
        assert!(!live.is_empty());
    });
}
