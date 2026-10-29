use std::cell::Cell;
use std::rc::Rc;

use rt::sim::{Config, SimDriver};
use rt::{Buf, File, JoinHandle, OpenOptions, Runtime, spawn};
use store::{
    Body, Claim, Client, Committer, DataFile, Dead, Error, Location, Options, Owner, READ_ATTEMPTS,
    Range, Reader, Record, SLOT_SIZE, Submission, Write, ZONE_SIZE, checksum, load, recover,
};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 2 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 8,
    shards: 4,
};

struct Fixed {
    answer: Option<Location>,
    calls: Cell<u32>,
}

impl Fixed {
    fn new(answer: Option<Location>) -> Self {
        Self {
            answer,
            calls: Cell::new(0),
        }
    }
}

impl Owner for Fixed {
    fn locate(&self, _: Location) -> impl Future<Output = Option<Location>> {
        self.calls.set(self.calls.get() + 1);
        std::future::ready(self.answer)
    }
}

fn run<T: 'static>(seed: u64, future: impl Future<Output = T> + 'static) -> T {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(future)
}

async fn start() -> (Client, Reader, JoinHandle<Committer>) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
    let reader = committer.reader();
    (client, reader, spawn(committer.run()))
}

async fn commit(client: &Client, tenant: u32, payload: &[u8]) -> Location {
    let durable = client
        .commit(Submission {
            claim: Claim::Intake,
            records: vec![Write {
                kind: 7,
                counted: true,
                shard: 0,
                tenant,
                payload: payload.to_vec(),
            }],
            bodies: Vec::new(),
            dead: Vec::new(),
        })
        .await
        .expect("commit");
    durable.locations[0]
}

async fn write_raw(region: u32, offset: u64, bytes: &[u8]) {
    let options = OpenOptions {
        read: true,
        write: true,
        ..OpenOptions::default()
    };
    let file = File::open(PATH, &options).await.expect("open raw");
    let at = ZONE_SIZE + OPTIONS.journal_size + u64::from(region) * OPTIONS.region_size + offset;
    let (result, _) = file.write_all_at(Buf::from_slice(bytes), at).await;
    result.expect("write raw");
}

fn payload(buf: &Buf) -> Vec<u8> {
    Record::decode(buf).expect("decode").payload().to_vec()
}

#[test]
fn a_committed_record_reads_back() {
    run(1, async {
        let (client, reader, _committer) = start().await;
        let location = commit(&client, 3, b"hello reader").await;
        let owner = Fixed::new(None);
        let buf = reader.read(location, 3, &owner).await.expect("read");
        assert_eq!(payload(&buf), b"hello reader");
        assert_eq!(owner.calls.get(), 0);
        assert!(!reader.pins().is_pinned(location.region));
    });
}

#[test]
fn a_stale_location_is_resolved_by_the_owner() {
    run(2, async {
        let (client, reader, _committer) = start().await;
        let location = commit(&client, 3, b"moved").await;
        let stale = Location {
            epoch: location.epoch + 1,
            ..location
        };
        let owner = Fixed::new(Some(location));
        let buf = reader.read(stale, 3, &owner).await.expect("read");
        assert_eq!(payload(&buf), b"moved");
        assert_eq!(owner.calls.get(), 1);
    });
}

#[test]
fn a_record_of_another_tenant_is_never_returned() {
    run(3, async {
        let (client, reader, _committer) = start().await;
        let location = commit(&client, 3, b"private").await;
        let owner = Fixed::new(Some(location));
        let read = reader.read(location, 4, &owner).await;
        assert!(matches!(
            read,
            Err(Error::Damaged { region, offset })
                if region == location.region && offset == location.offset
        ));
        assert_eq!(owner.calls.get(), READ_ATTEMPTS);
    });
}

#[test]
fn a_deleted_record_is_not_found() {
    run(4, async {
        let (client, reader, _committer) = start().await;
        let location = commit(&client, 3, b"gone").await;
        let wrong = Location {
            sequence: location.sequence + 100,
            ..location
        };
        let read = reader.read(wrong, 3, &Fixed::new(None)).await;
        assert!(matches!(read, Err(Error::NotFound)));
    });
}

#[test]
fn locations_outside_the_file_ask_the_owner() {
    run(5, async {
        let (client, reader, _committer) = start().await;
        let location = commit(&client, 3, b"inside").await;
        let owner = Fixed::new(Some(location));
        for outside in [
            Location {
                region: OPTIONS.region_count,
                ..location
            },
            Location {
                offset: OPTIONS.region_size - 8,
                ..location
            },
            Location {
                offset: u64::MAX,
                ..location
            },
        ] {
            let buf = reader.read(outside, 3, &owner).await.expect("read");
            assert_eq!(payload(&buf), b"inside");
        }
        assert_eq!(owner.calls.get(), 3);
    });
}

#[test]
fn corrupt_bytes_are_reported_as_damage() {
    run(6, async {
        let (client, reader, _committer) = start().await;
        let location = commit(&client, 3, &[9u8; 200]).await;
        write_raw(location.region, location.offset + 100, &[0u8; 4]).await;
        let owner = Fixed::new(Some(location));
        let read = reader.read(location, 3, &owner).await;
        assert!(matches!(read, Err(Error::Damaged { .. })));
        assert_eq!(owner.calls.get(), READ_ATTEMPTS);
    });
}

fn region_after_pinning(seed: u64, pinned: u32, unpinned: u32) -> bool {
    run(seed, async move {
        let (client, reader, committer) = start().await;
        let lease = client.allocate(Claim::Intake).await.expect("allocate");
        let (region, epoch) = (lease.region(), lease.epoch());
        let bytes = vec![5u8; 4096];
        write_raw(region, 0, &bytes).await;
        let range = Range {
            region,
            epoch,
            offset: 0,
            length: 4096,
            checksum: checksum(&bytes),
        };
        let body = Submission {
            claim: Claim::Intake,
            records: Vec::new(),
            bodies: vec![Body {
                shard: 0,
                tenant: 4,
                range,
            }],
            dead: Vec::new(),
        };
        client.commit(body).await.expect("commit body");
        let kill = Submission {
            claim: Claim::Intake,
            records: Vec::new(),
            bodies: Vec::new(),
            dead: vec![Dead {
                tenant: 4,
                region,
                epoch,
                offset: 0,
                length: 4096,
            }],
        };
        client.commit(kill).await.expect("kill");
        lease.seal();
        let pin = reader.pins().pin(region);
        for _ in 0..pinned {
            client.checkpoint().await.expect("checkpoint");
        }
        drop(pin);
        for _ in 0..unpinned {
            client.checkpoint().await.expect("checkpoint");
        }
        drop(client);
        let committer = committer.await;
        committer.regions().is_used(region)
    })
}

#[test]
fn a_pinned_region_is_not_freed() {
    assert!(region_after_pinning(7, 1, 0));
}

#[test]
fn an_unpinned_region_is_freed_by_the_next_checkpoint() {
    assert!(!region_after_pinning(7, 1, 1));
}
