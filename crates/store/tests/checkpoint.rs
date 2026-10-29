use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, SimDriver, check};
use rt::{Buf, File, JoinHandle, OpenOptions, Runtime, sleep, spawn};
use store::{
    Body, CHECKPOINT_RESERVE, Claim, Client, Committer, DataFile, Durable, Error, Location,
    Options, Range, Record, Recovered, SLOT_SIZE, Submission, Write, checksum, load, recover,
};

const MILLION: u32 = 1_000_000;
const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 2 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

type Acked = Vec<(Durable, Vec<Vec<u8>>)>;

fn run<T: 'static>(driver: &Rc<SimDriver>, future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(driver.clone()).block_on(future)
}

fn created(seed: u64) -> Rc<SimDriver> {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    run(&setup, async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    Rc::new(SimDriver::with_disk(seed, Config::default(), setup.crash()))
}

async fn reopen() -> (DataFile, Result<Recovered, Error>) {
    let data = DataFile::open(PATH).await.expect("open");
    let recovered = match load(&data, 0).await {
        Ok(loaded) => recover(&data, loaded.position, loaded.state).await,
        Err(e) => Err(e),
    };
    (data, recovered)
}

async fn start() -> (Client, JoinHandle<Committer>) {
    let (data, recovered) = reopen().await;
    let recovered = recovered.expect("recover");
    let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
    (client, spawn(committer.run()))
}

fn payload(client: u64, step: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&client.to_le_bytes());
    out.extend_from_slice(&step.to_le_bytes());
    out.resize(len.max(16), u8::try_from(step % 251).expect("fits"));
    out
}

fn submission(records: Vec<Vec<u8>>) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: records
            .into_iter()
            .map(|payload| Write {
                kind: 7,
                tenant: 3,
                payload,
            })
            .collect(),
        bodies: Vec::new(),
        dead: Vec::new(),
    }
}

async fn read(data: &DataFile, location: Location) -> Vec<u8> {
    let offset = data.region_offset(location.region) + location.offset;
    let len = location.size as usize;
    let (result, buf) = data.file().read_at(Buf::new(len), offset).await;
    assert_eq!(result.expect("read"), len);
    let record = Record::decode(&buf).expect("record decodes");
    assert_eq!(record.epoch(), location.epoch);
    assert_eq!(record.sequence(), location.sequence);
    record.payload().to_vec()
}

async fn raw_write(at: u64, bytes: &[u8]) {
    let file = File::open(PATH, &OPTIONS_RW).await.expect("open raw");
    let (result, _) = file.write_all_at(Buf::from_slice(bytes), at).await;
    result.expect("raw write");
    file.sync_data().await.expect("sync");
}

const OPTIONS_RW: OpenOptions = OpenOptions {
    read: true,
    write: true,
    create: false,
    create_new: false,
    truncate: false,
};

fn used(recovered: &Recovered) -> BTreeSet<u32> {
    (0..OPTIONS.region_count)
        .filter(|&r| recovered.state.regions.is_used(r))
        .collect()
}

async fn commit_some(client: &Client, from: u64, count: u64, acked: &mut Acked) {
    for step in from..from + count {
        let records = vec![payload(1, step, 200)];
        let durable = client
            .commit(submission(records.clone()))
            .await
            .expect("commit");
        acked.push((durable, records));
    }
}

async fn verify(data: &DataFile, acked: &Acked) {
    for (durable, records) in acked {
        for (location, expected) in durable.locations.iter().zip(records) {
            assert_eq!(&read(data, *location).await, expected);
        }
    }
}

#[test]
fn recovery_starts_from_the_checkpoint() {
    let driver = created(1);
    run(&driver, async {
        let (client, committer) = start().await;
        let mut acked = Vec::new();
        commit_some(&client, 0, 3, &mut acked).await;
        let cut = client.checkpoint().await.expect("checkpoint");
        assert_eq!(cut, 4);
        commit_some(&client, 3, 2, &mut acked).await;
        drop(client);
        let committer = committer.await;
        let live: BTreeSet<u32> = (0..OPTIONS.region_count)
            .filter(|&r| committer.regions().is_used(r))
            .collect();
        drop(committer);
        let (data, recovered) = reopen().await;
        let recovered = recovered.expect("recover");
        let sequences: Vec<u64> = recovered.entries.iter().map(|e| e.sequence).collect();
        assert_eq!(sequences, vec![4, 5]);
        assert_eq!(used(&recovered), live);
        assert_eq!(recovered.state.checkpoint.len(), 2);
        let last = acked.last().expect("acked").0.locations[0].sequence;
        assert_eq!(recovered.state.record_sequence, last + 1);
        verify(&data, &acked).await;
    });
}

#[test]
fn the_journal_wraps_forever_and_old_checkpoints_are_released() {
    let driver = created(2);
    run(&driver, async {
        let (client, committer) = start().await;
        let mut acked = Vec::new();
        commit_some(&client, 0, 300, &mut acked).await;
        drop(client);
        let committer = committer.await;
        let sequence = committer.data().superblock().sequence();
        assert!(sequence > 5, "checkpoints ran: superblock {sequence}");
        let live = (0..OPTIONS.region_count)
            .filter(|&r| committer.regions().is_used(r))
            .count();
        drop(committer);
        let (data, recovered) = reopen().await;
        let recovered = recovered.expect("recover");
        assert_eq!(used(&recovered).len(), live, "no region leaked");
        verify(&data, &acked).await;
        drop(data);
        drop(recovered);
        let (client, committer) = start().await;
        client.checkpoint().await.expect("checkpoint");
        client.checkpoint().await.expect("checkpoint");
        drop(client);
        let committer = committer.await;
        let after = (0..OPTIONS.region_count)
            .filter(|&r| committer.regions().is_used(r))
            .count();
        assert_eq!(
            after, live,
            "repeated checkpoints release their predecessors"
        );
    });
}

#[test]
fn the_second_copy_is_used_when_the_first_is_damaged() {
    let driver = created(3);
    run(&driver, async {
        let (client, committer) = start().await;
        let mut acked = Vec::new();
        commit_some(&client, 0, 2, &mut acked).await;
        client.checkpoint().await.expect("checkpoint");
        drop(client);
        let committer = committer.await;
        let copies = committer
            .data()
            .superblock()
            .checkpoint()
            .expect("checkpoint")
            .copies;
        let offsets = copies.map(|c| committer.data().region_offset(c.region));
        drop(committer);
        raw_write(offsets[0] + 100, &[0x5A; 32]).await;
        let (data, recovered) = reopen().await;
        let recovered = recovered.expect("second copy");
        assert_eq!(recovered.entries.len(), 0);
        verify(&data, &acked).await;
        drop(data);
        raw_write(offsets[1] + 100, &[0x5A; 32]).await;
        let (_, lost) = reopen().await;
        assert!(matches!(lost, Err(Error::CheckpointLost)));
    });
}

#[test]
fn allocations_not_yet_committed_stay_out_of_the_checkpoint() {
    let driver = created(4);
    run(&driver, async {
        let (client, committer) = start().await;
        let lease = client.allocate(Claim::Intake).await.expect("allocate");
        let pending = lease.region();
        let chain = client.allocate(Claim::Intake).await.expect("allocate");
        let (body, epoch) = (chain.region(), chain.epoch());
        client.checkpoint().await.expect("checkpoint");
        let bytes = vec![3u8; 4096];
        let data_offset = {
            let (data, snapshot) = reopen().await;
            let snapshot = snapshot.expect("recover at the checkpoint");
            assert!(!snapshot.state.regions.is_used(pending));
            assert!(!snapshot.state.regions.is_used(body));
            assert_eq!(snapshot.state.epochs[body as usize], epoch - 1);
            data.region_offset(body)
        };
        raw_write(data_offset, &bytes).await;
        client
            .commit(Submission {
                bodies: vec![Body {
                    tenant: 3,
                    range: Range {
                        region: body,
                        epoch,
                        offset: 0,
                        length: 4096,
                        checksum: checksum(&bytes),
                    },
                }],
                ..submission(Vec::new())
            })
            .await
            .expect("commit range");
        drop((lease, chain));
        drop(client);
        committer.await;
        let (_, recovered) = reopen().await;
        let recovered = recovered.expect("recover");
        assert!(recovered.state.regions.is_used(body));
        assert_eq!(recovered.state.epochs[body as usize], epoch);
        assert!(
            recovered.state.regions.is_used(pending),
            "journaled by the commit"
        );
    });
}

#[test]
fn a_full_store_can_still_checkpoint() {
    let driver = created(5);
    run(&driver, async {
        let (client, committer) = start().await;
        while client.allocate(Claim::Internal).await.is_ok() {}
        let free = client.allocate(Claim::Checkpoint).await;
        assert!(free.is_ok(), "the checkpoint reserve is kept");
        drop(free);
        drop(client);
        let committer = committer.await;
        assert_eq!(committer.regions().free(), CHECKPOINT_RESERVE - 1);
    });
}

#[test]
fn acknowledged_records_survive_crashes_during_checkpoints() {
    check(0..100, |seed| {
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let config = Config {
            faults,
            ..Config::default()
        };
        let mut disk = created(seed).crash();
        let acked: Rc<RefCell<Acked>> = Rc::default();
        for round in 0..3u64 {
            let driver = Rc::new(SimDriver::with_disk(seed * 4 + round, config.clone(), disk));
            let out = acked.clone();
            let wait = Duration::from_micros(driver.random() % 80_000);
            run(&driver, async move {
                let (client, _committer) = start().await;
                for id in 0..3u64 {
                    let client = client.clone();
                    let acked = out.clone();
                    spawn(async move {
                        for step in 0..40u64 {
                            let len = 30 + usize::try_from(step).expect("fits") * 23;
                            let records = vec![payload(round * 10 + id, step, len)];
                            if let Ok(durable) = client.commit(submission(records.clone())).await {
                                acked.borrow_mut().push((durable, records));
                            }
                        }
                    });
                }
                sleep(wait).await;
            });
            disk = driver.crash();
        }
        let driver = Rc::new(SimDriver::with_disk(seed * 4 + 3, Config::default(), disk));
        let acked = acked.take();
        run(&driver, async move {
            let (data, recovered) = reopen().await;
            let recovered = recovered.expect("recover after crashes");
            let mut seen = BTreeSet::new();
            for (durable, records) in &acked {
                for (location, expected) in durable.locations.iter().zip(records) {
                    assert!(seen.insert(location.sequence), "sequence reused");
                    assert!(recovered.state.regions.is_used(location.region));
                    assert_eq!(&read(&data, *location).await, expected);
                }
            }
        });
    });
}
