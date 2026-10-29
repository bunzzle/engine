use std::rc::Rc;

use rt::sim::{Config, SimDriver};
use rt::{Buf, Runtime, spawn};
use store::{
    BODY_SIZE, Change, Claim, Committer, DataFile, Delivery, INDEX_SIZE, Index, Key, Location,
    Options, Parts, Range, Record, SLOT_SIZE, ShardState, Submission, Write, load, recover,
};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

fn range(n: u64) -> Range {
    Range {
        region: 5,
        epoch: 3,
        offset: n * 4096,
        length: 4096,
        checksum: 0xFEED,
    }
}

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
        key: Key::head(key),
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
            key: Key::new(6, 3),
            tenant: 7,
            change: Change::Delete,
        },
        Index {
            key: Key::new(6, 0),
            tenant: 7,
            change: Change::Drop,
        },
        Index {
            key: Key::new(7, u32::MAX),
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
        let bodies = [range(1), range(2)];
        let record = index.record(b"clear", &bodies, b"sealed");
        let parts = Parts {
            index,
            clear: b"clear",
            bodies: bodies.to_vec(),
            sealed: b"sealed",
        };
        assert_eq!(Index::parts(&record), Some(parts));
    }
    let good = put(1, 1).payload(&[]);
    let mut long = put(1, 1).record(b"abc", &[], b"");
    long[28] = 4;
    assert_eq!(Index::decode(&long), None, "clear part past the end");
    let with_body = put(1, 1).record(b"abc", &[range(1)], b"");
    let mut many = with_body.clone();
    many[64] = 2;
    assert_eq!(Index::decode(&many), None, "bodies past the end");
    let mut body_reserved = with_body.clone();
    body_reserved[INDEX_SIZE + 3 + BODY_SIZE - 1] = 1;
    assert_eq!(Index::decode(&body_reserved), None);
    let mut empty = with_body;
    empty[INDEX_SIZE + 3 + 4..INDEX_SIZE + 3 + 8].fill(0);
    assert_eq!(Index::decode(&empty), None, "empty body range");
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
    state.apply(&put(1, 1), &[], &[], location(1, 0), 10);
    state.apply(&put(2, 1), &[], &[], location(1, 128), 11);
    state.apply(&put(1, 3), &[], &[], location(1, 256), 12);
    assert_eq!(state.get(Key::head(1)).map(|e| e.delivery.status), Some(3));
    assert_eq!(
        state.get(Key::head(1)).map(|e| e.location),
        Some(location(1, 256))
    );
    let outdated = Index {
        key: Key::head(1),
        tenant: 7,
        change: Change::Move {
            old: location(1, 0),
        },
    };
    state.apply(&outdated, &[], &[], location(2, 0), 13);
    assert_eq!(
        state.get(Key::head(1)).map(|e| e.location),
        Some(location(1, 256))
    );
    let moved = Index {
        key: Key::head(1),
        tenant: 7,
        change: Change::Move {
            old: location(1, 256),
        },
    };
    state.apply(&moved, &[], &[], location(2, 128), 14);
    assert_eq!(
        state.get(Key::head(1)).map(|e| e.location),
        Some(location(2, 128))
    );
    assert_eq!(state.get(Key::head(1)).map(|e| e.delivery.status), Some(3));
    let delete = Index {
        key: Key::head(2),
        tenant: 7,
        change: Change::Delete,
    };
    state.apply(&delete, &[], &[], location(2, 256), 15);
    assert_eq!(state.get(Key::head(2)), None);
    assert_eq!(state.len(), 1);
    assert_eq!(state.covered(), 15);
}

#[test]
fn drop_removes_one_message_and_moves_replace_the_clear_part() {
    let mut state = ShardState::default();
    for (message, item, at) in [
        (1, 0, 0),
        (1, 4, 128),
        (1, u32::MAX, 256),
        (2, 0, 384),
        (0, 9, 512),
    ] {
        let index = Index {
            key: Key::new(message, item),
            ..put(message, 1)
        };
        state.apply(&index, b"old", &[], location(1, at), at);
    }
    state.freeze(600);
    let moved = Index {
        key: Key::new(2, 0),
        tenant: 7,
        change: Change::Move {
            old: location(1, 384),
        },
    };
    state.apply(&moved, b"new", &[], location(2, 0), 601);
    let drop = Index {
        key: Key::head(1),
        tenant: 7,
        change: Change::Drop,
    };
    state.apply(&drop, &[], &[], location(2, 128), 602);
    let left: Vec<Key> = state.entries().keys().copied().collect();
    assert_eq!(left, vec![Key::new(0, 9), Key::new(2, 0)]);
    assert_eq!(state.message(1).count(), 0);
    assert_eq!(&*state.get(Key::new(2, 0)).expect("moved").clear, b"new");
    let delta = state.freeze(602);
    let tombstones: Vec<Key> = delta
        .changes
        .iter()
        .filter(|(_, v)| v.is_none())
        .map(|(&k, _)| k)
        .collect();
    assert_eq!(
        tombstones,
        vec![Key::new(1, 0), Key::new(1, 4), Key::new(1, u32::MAX)]
    );
}

#[test]
fn frozen_deltas_are_copies_and_restore_under_newer_changes() {
    let mut state = ShardState::default();
    state.apply(&put(1, 1), &[], &[], location(1, 0), 1);
    state.apply(&put(2, 1), &[], &[], location(1, 128), 2);
    let frozen = state.freeze(2);
    assert_eq!(frozen.covered, 2);
    assert_eq!(frozen.changes.len(), 2);
    state.apply(&put(1, 5), &[], &[], location(1, 256), 3);
    let delete = Index {
        key: Key::head(2),
        tenant: 7,
        change: Change::Delete,
    };
    state.apply(&delete, &[], &[], location(1, 384), 4);
    assert_eq!(
        frozen.changes[&Key::head(1)]
            .as_ref()
            .map(|e| e.delivery.status),
        Some(1),
        "a frozen delta keeps its values"
    );
    state.restore(frozen);
    let merged = state.freeze(4);
    assert_eq!(
        merged.changes[&Key::head(1)]
            .as_ref()
            .map(|e| e.delivery.status),
        Some(5)
    );
    assert_eq!(merged.changes[&Key::head(2)], None);
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
        for step in 0..90u64 {
            let key = Key::new(step % 4, u32::try_from(step % 3).expect("fits"));
            let index = match step % 7 {
                3 => live.get(key).map_or(put(key.message, 1), |entry| Index {
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
                6 => Index {
                    key,
                    tenant: 7,
                    change: Change::Drop,
                },
                _ => Index {
                    key,
                    ..put(key.message, u8::try_from(step % 200).expect("fits"))
                },
            };
            let clear =
                vec![u8::try_from(step).expect("fits"); usize::try_from(step % 5).expect("fits")];
            let bodies: Vec<Range> = (0..step % 3).map(|n| range(step * 4 + n)).collect();
            let submission = Submission {
                claim: Claim::Intake,
                records: vec![Write {
                    kind: 9,
                    counted: true,
                    shard: 1,
                    tenant: 7,
                    payload: index.record(&clear, &bodies, &[0xAB; 40]),
                }],
                bodies: Vec::new(),
                dead: Vec::new(),
            };
            let durable = client.commit(submission).await.expect("commit");
            live.apply(
                &index,
                &clear,
                &bodies,
                durable.locations[0],
                durable.sequence,
            );
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
            let parts = Index::parts(record.payload()).expect("index part");
            replayed.apply(&parts.index, parts.clear, &parts.bodies, location, sequence);
        }
        assert_eq!(replayed.entries(), live.entries());
        assert_eq!(replayed.covered(), live.covered());
        assert!(!live.is_empty());
        assert!(live.entries().values().any(|item| !item.clear.is_empty()));
        assert!(live.entries().values().any(|item| item.bodies.len() == 2));
    });
}
