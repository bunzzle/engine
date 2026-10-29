use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, Faults, SimDriver, check};
use rt::{Buf, File, JoinHandle, OpenOptions, Runtime, sleep, spawn};
use store::{
    Body, Claim, Client, Committer, Count, DataFile, Dead, Error, Location, Options, Range, Record,
    Recovered, SLOT_SIZE, Submission, Write, ZONE_SIZE, checksum, load, recover,
};

const MILLION: u32 = 1_000_000;
const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 2 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

type Tracked = Rc<RefCell<VecDeque<(Location, Vec<u8>)>>>;

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

async fn reopen() -> (DataFile, Recovered) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    (data, recovered)
}

async fn start() -> (Client, JoinHandle<Committer>) {
    let (data, recovered) = reopen().await;
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

fn submission(tenant: u32, records: Vec<Vec<u8>>, dead: Vec<Dead>) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: records
            .into_iter()
            .map(|payload| Write {
                kind: 7,
                shard: 0,
                tenant,
                payload,
            })
            .collect(),
        bodies: Vec::new(),
        dead,
    }
}

fn dead(tenant: u32, location: &Location) -> Dead {
    Dead {
        tenant,
        region: location.region,
        epoch: location.epoch,
        offset: location.offset,
        length: location.size,
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

async fn write_body(region: u32, bytes: &[u8]) {
    let options = OpenOptions {
        read: true,
        write: true,
        ..OpenOptions::default()
    };
    let file = File::open(PATH, &options).await.expect("open raw");
    let at = ZONE_SIZE + OPTIONS.journal_size + u64::from(region) * OPTIONS.region_size;
    let (result, _) = file.write_all_at(Buf::from_slice(bytes), at).await;
    result.expect("write body");
}

fn size(location: &Location) -> u64 {
    u64::from(location.size)
}

#[test]
fn counts_follow_commits_and_survive_a_restart() {
    let driver = created(1);
    run(&driver, async {
        let (client, committer) = start().await;
        let first = client
            .commit(submission(
                3,
                vec![payload(0, 0, 100), payload(0, 1, 300), payload(0, 2, 50)],
                Vec::new(),
            ))
            .await
            .expect("commit");
        let other = client
            .commit(submission(7, vec![payload(1, 0, 200)], Vec::new()))
            .await
            .expect("commit");
        client
            .commit(submission(
                3,
                Vec::new(),
                vec![dead(3, &first.locations[1])],
            ))
            .await
            .expect("kill");
        drop(client);
        let committer = committer.await;
        let usage = committer.usage().clone();
        let region = first.locations[0].region;
        let three = size(&first.locations[0]) + size(&first.locations[2]);
        let seven = size(&other.locations[0]);
        assert_eq!(
            usage.count(region),
            Count {
                extents: 3,
                bytes: three + seven,
            }
        );
        assert_eq!(usage.tenant(3), three);
        assert_eq!(usage.tenant(7), seven);
        drop(committer);

        let (_, replayed) = reopen().await;
        assert_eq!(replayed.state.usage, usage, "rebuilt by replay");

        let (client, committer) = start().await;
        client.checkpoint().await.expect("checkpoint");
        drop(client);
        drop(committer.await);
        let (_, loaded) = reopen().await;
        assert_eq!(loaded.entries.len(), 0);
        assert_eq!(loaded.state.usage, usage, "loaded from the checkpoint");
    });
}

#[test]
fn bad_dead_entries_are_refused() {
    let driver = created(2);
    run(&driver, async {
        let (client, committer) = start().await;
        let durable = client
            .commit(submission(
                3,
                vec![payload(0, 0, 100), payload(0, 1, 100)],
                Vec::new(),
            ))
            .await
            .expect("commit");
        let [a, b] = [durable.locations[0], durable.locations[1]];
        let region = a.region;
        let lease = client.allocate(Claim::Intake).await.expect("allocate");
        let stale = Dead {
            epoch: lease.epoch() + 5,
            ..dead(3, &a)
        };
        let refused = client.commit(submission(3, Vec::new(), vec![stale])).await;
        assert!(matches!(refused, Err(Error::Invalid("dead"))));
        let wrong_tenant = client
            .commit(submission(9, Vec::new(), vec![dead(9, &a)]))
            .await;
        assert!(matches!(wrong_tenant, Err(Error::Invalid("dead"))));
        client
            .commit(submission(3, Vec::new(), vec![dead(3, &a), dead(3, &b)]))
            .await
            .expect("kill both");
        let twice = client
            .commit(submission(3, vec![payload(0, 2, 10)], vec![dead(3, &a)]))
            .await;
        assert!(matches!(twice, Err(Error::Invalid("dead"))));
        client.checkpoint().await.expect("checkpoint");
        drop(lease);
        drop(client);
        let committer = committer.await;
        assert!(committer.usage().is_quarantined(region));
        assert_eq!(committer.usage().count(region), Count::default());
        assert_eq!(committer.usage().tenant(3), 0);
        assert!(committer.regions().is_used(region));
        drop(committer);

        let (client, committer) = start().await;
        client.checkpoint().await.expect("checkpoint");
        drop(client);
        let committer = committer.await;
        assert!(
            committer.regions().is_used(region),
            "a quarantined region is never freed"
        );
        assert!(committer.usage().is_quarantined(region));
    });
}

#[test]
fn empty_sealed_regions_are_freed_by_the_next_checkpoint() {
    let driver = created(3);
    run(&driver, async {
        let (client, committer) = start().await;
        let stream = client
            .commit(submission(3, vec![payload(0, 0, 100)], Vec::new()))
            .await
            .expect("commit");
        let stream = stream.locations[0];
        let lease = client.allocate(Claim::Intake).await.expect("allocate");
        let (region, epoch) = (lease.region(), lease.epoch());
        let bytes = vec![5u8; 4096];
        write_body(region, &bytes).await;
        let range = Range {
            region,
            epoch,
            offset: 0,
            length: 4096,
            checksum: checksum(&bytes),
        };
        client
            .commit(Submission {
                bodies: vec![Body { tenant: 4, range }],
                ..submission(4, Vec::new(), Vec::new())
            })
            .await
            .expect("commit body");
        let body = Dead {
            tenant: 4,
            region,
            epoch,
            offset: 0,
            length: 4096,
        };
        client
            .commit(submission(3, Vec::new(), vec![body, dead(3, &stream)]))
            .await
            .expect("kill");
        client.checkpoint().await.expect("checkpoint");
        lease.seal();
        client.checkpoint().await.expect("checkpoint");
        let late = client
            .commit(Submission {
                bodies: vec![Body { tenant: 4, range }],
                ..submission(4, Vec::new(), Vec::new())
            })
            .await;
        assert!(
            matches!(late, Err(Error::Invalid("range"))),
            "a freed region takes no ranges"
        );
        let again = client.allocate(Claim::Intake).await.expect("allocate");
        if again.region() == region {
            assert!(again.epoch() > epoch);
        }
        drop(again);
        drop(client);
        let committer = committer.await;
        assert!(
            committer.regions().is_used(stream.region),
            "the open stream stays"
        );
        drop(committer);

        let (_, recovered) = reopen().await;
        assert!(recovered.state.usage.is_empty(stream.region));
        let (client, committer) = start().await;
        client.checkpoint().await.expect("checkpoint");
        drop(client);
        let committer = committer.await;
        assert!(
            !committer.regions().is_used(stream.region),
            "sealed after restart, freed"
        );
    });
}

async fn churn(client: Client, id: u64, steps: u64, live: Tracked, failures: Rc<RefCell<u64>>) {
    for step in 0..steps {
        let len = 200 + usize::try_from((step * 37 + id * 11) % 1800).expect("fits");
        let record = payload(id, step, len);
        let kill = {
            let mut live = live.borrow_mut();
            if live.len() > 6 {
                live.pop_front()
            } else {
                None
            }
        };
        let dead = kill.iter().map(|(l, _)| dead(3, l)).collect();
        match client
            .commit(submission(3, vec![record.clone()], dead))
            .await
        {
            Ok(durable) => live.borrow_mut().push_back((durable.locations[0], record)),
            Err(_) => *failures.borrow_mut() += 1,
        }
        if step % 50 == 49 {
            let _ = client.checkpoint().await;
        }
    }
}

async fn verify(data: &DataFile, recovered: &Recovered, live: &[Tracked]) {
    for tracked in live {
        let records: Vec<_> = tracked.borrow().iter().cloned().collect();
        for (location, expected) in &records {
            assert!(recovered.state.regions.is_used(location.region));
            assert_eq!(
                recovered.state.epochs[location.region as usize],
                location.epoch
            );
            assert_eq!(&read(data, *location).await, expected);
        }
    }
    for region in 0..OPTIONS.region_count {
        if !recovered.state.regions.is_used(region) {
            assert!(recovered.state.usage.is_empty(region));
        }
    }
}

#[test]
fn regions_are_reused_under_churn() {
    let driver = created(4);
    let live: Vec<Tracked> = (0..3).map(|_| Tracked::default()).collect();
    let failures = Rc::new(RefCell::new(0));
    let tracked = live.clone();
    let failed = failures.clone();
    run(&driver, async move {
        let (client, committer) = start().await;
        let mut tasks = Vec::new();
        for (id, live) in (0u64..).zip(&tracked) {
            tasks.push(spawn(churn(
                client.clone(),
                id,
                700,
                live.clone(),
                failed.clone(),
            )));
        }
        for task in tasks {
            task.await;
        }
        drop(client);
        drop(committer.await);
        let (data, recovered) = reopen().await;
        verify(&data, &recovered, &tracked).await;
    });
    assert_eq!(*failures.borrow(), 0, "every commit fits after reuse");
}

#[test]
fn live_records_survive_crashes_while_regions_are_reused() {
    check(0..60, |seed| {
        let faults = Faults {
            torn_write: MILLION / 4,
            ..Faults::default()
        };
        let config = Config {
            faults,
            ..Config::default()
        };
        let mut disk = created(seed).crash();
        let live: Vec<Tracked> = (0..3).map(|_| Tracked::default()).collect();
        for round in 0..3u64 {
            let driver = Rc::new(SimDriver::with_disk(seed * 4 + round, config.clone(), disk));
            let tracked = live.clone();
            let wait = Duration::from_micros(driver.random() % 150_000);
            run(&driver, async move {
                let (client, _committer) = start().await;
                for (id, live) in (0u64..).zip(&tracked) {
                    spawn(churn(
                        client.clone(),
                        round * 10 + id,
                        300,
                        live.clone(),
                        Rc::default(),
                    ));
                }
                sleep(wait).await;
            });
            disk = driver.crash();
        }
        let driver = Rc::new(SimDriver::with_disk(seed * 4 + 3, Config::default(), disk));
        run(&driver, async move {
            let (data, recovered) = reopen().await;
            verify(&data, &recovered, &live).await;
        });
    });
}
