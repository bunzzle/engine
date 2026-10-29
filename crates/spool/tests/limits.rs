use std::rc::Rc;

use rt::sim::{Config, SimDriver};
use rt::{Runtime, spawn};
use spool::{Body, Error, Head, HeadClear, Limits, Message, MessageId, SLICE, Slice, Spool};
use store::{DataFile, INDEX_SIZE, Ids, MAX_PAYLOAD, Options, SLOT_SIZE, Setup, boot, split_key};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 32,
    shards: 2,
};

const LIMITS: Limits = Limits {
    recipients: 3000,
    inline: 1024,
    body: 64 * 1024,
};

#[test]
fn a_slice_of_the_largest_recipients_fits_one_record() {
    let per = 256 + 500 + 8 + 4;
    assert!(INDEX_SIZE + 4 + 64 + SLICE as usize * per <= MAX_PAYLOAD);
    assert!(INDEX_SIZE + 4 + 64 + (SLICE as usize + 1) * per > MAX_PAYLOAD);
}

fn head(recipients: usize) -> Head {
    Head {
        clear: HeadClear {
            recipients: u32::try_from(recipients).expect("fits"),
            ..HeadClear::default()
        },
        expiry: 9,
        sealed: vec![1; 100],
    }
}

fn slices(sizes: &[usize]) -> Vec<Slice> {
    sizes
        .iter()
        .map(|&n| Slice {
            queues: vec![4; n],
            sealed: vec![2; n],
        })
        .collect()
}

fn message(id: MessageId, sizes: &[usize]) -> Message {
    Message {
        id,
        tenant: 7,
        head: head(sizes.iter().sum()),
        body: Body::Inline(vec![3; 10]),
        slices: slices(sizes),
    }
}

fn refused(result: Result<(), Error>, what: &str) {
    match result {
        Err(Error::Limit(found)) if found == what => {}
        other => panic!("expected {what}, got {other:?}"),
    }
}

#[test]
fn limits_over_one_commit_or_a_record_are_refused_at_start() {
    for limits in [
        Limits {
            recipients: 40_000,
            ..LIMITS
        },
        Limits {
            recipients: 0,
            ..LIMITS
        },
        Limits {
            inline: MAX_PAYLOAD,
            ..LIMITS
        },
        Limits {
            body: 64 * 1024 * 1024 * 1024,
            ..LIMITS
        },
    ] {
        assert!(matches!(
            limits.validate(OPTIONS.region_size),
            Err(Error::Limit(_))
        ));
    }
    LIMITS.validate(OPTIONS.region_size).expect("test limits");
}

#[test]
fn intake_refuses_messages_over_the_limits() {
    let setup = Rc::new(SimDriver::new(1, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(1, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(async {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
        };
        let booted = boot(PATH, setup).await.expect("boot");
        let committer = spawn(booted.committer.run());
        let core = booted
            .starts
            .into_iter()
            .next()
            .expect("core")
            .open()
            .await
            .expect("open");
        let (intake, owner) = Spool::new(core, 1, LIMITS).expect("limits");
        let owner = spawn(owner.run());
        let id = intake.id(0).await.expect("id");
        let full = SLICE as usize;
        refused(intake.accept(vec![message(id, &[])]).await, "recipients");
        refused(
            intake.accept(vec![message(id, &[full, full, full])]).await,
            "recipients",
        );
        refused(
            intake.accept(vec![message(id, &[5, 10])]).await,
            "recipients",
        );
        let mut total = message(id, &[3]);
        total.head.clear.recipients = 4;
        refused(intake.accept(vec![total]).await, "recipient total");
        let mut header = message(id, &[3]);
        header.head.sealed = vec![1; MAX_PAYLOAD];
        refused(intake.accept(vec![header]).await, "header");
        let mut inline = message(id, &[3]);
        inline.body = Body::Inline(vec![3; 1025]);
        refused(intake.accept(vec![inline]).await, "inline body");
        let other = intake.id(0).await.expect("id");
        let written = intake.body(other, 7, &[vec![5; 100]]).await.expect("body");
        let mut owner_body = message(id, &[3]);
        owner_body.body = Body::Chain(written);
        refused(intake.accept(vec![owner_body]).await, "body owner");
        let too_big = vec![0; intake.chunk() + 1];
        assert!(matches!(
            intake.body(id, 7, &[too_big]).await,
            Err(Error::Limit("chunk"))
        ));
        let many = vec![vec![0; 30_000]; 3];
        assert!(matches!(
            intake.body(id, 7, &many).await,
            Err(Error::Limit("body"))
        ));
        let mut wide = Vec::new();
        for _ in 0..4 {
            let id = intake.id(0).await.expect("id");
            let mut m = message(id, &[1000]);
            m.slices[0].sealed = vec![2; 30_000];
            wide.push(m);
        }
        refused(intake.accept(wide).await, "submission");
        assert!(matches!(
            intake.id(5).await,
            Err(Error::Store(store::Error::Invalid("owner")))
        ));
        intake
            .accept(vec![message(id, &[3])])
            .await
            .expect("accept");
        assert!(matches!(
            intake.accept(vec![message(id, &[3])]).await,
            Err(Error::Store(store::Error::Invalid("exists")))
        ));
        intake.changes().close();
        let keeper = owner.await;
        assert_eq!(keeper.state(0).expect("kept").message(id.key).count(), 3);
        drop(intake);
        drop(booted.client);
        drop(committer.await);
    });
}

#[test]
fn ids_take_a_new_boot_when_the_counter_runs_out() {
    let setup = Rc::new(SimDriver::new(2, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(2, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(async {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
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
        let first = core.ids.boot(0).expect("boot");
        core.ids = Ids::starting_at(first, &core.shards, u32::MAX);
        let (intake, owner) = Spool::new(core, 1, LIMITS).expect("limits");
        let owner = spawn(owner.run());
        let last = intake.id(0).await.expect("id");
        assert_eq!(split_key(last.key), (first, u32::MAX));
        let renewed = intake.id(0).await.expect("renewed id");
        assert_eq!(split_key(renewed.key), (first + 1, 1));
        let spent = intake.id(1).await.expect("last id of shard 1");
        assert_eq!(split_key(spent.key), (first, u32::MAX));
        let racing: Vec<_> = (0..2)
            .map(|_| {
                let intake = intake.clone();
                spawn(async move { intake.id(1).await.expect("racing id") })
            })
            .collect();
        let mut raced = Vec::new();
        for task in racing {
            raced.push(split_key(task.await.key));
        }
        raced.sort_unstable();
        assert!(raced[0].0 > first + 1);
        assert_eq!(raced[1], (raced[0].0, raced[0].1 + 1));
        assert_eq!(
            last.bytes()[8..],
            [first.to_le_bytes(), u32::MAX.to_le_bytes()].concat()[..]
        );
        assert_eq!(last.bytes()[..8], [1, 0, 0, 0, 0, 0, 0, 0]);
        intake.changes().close();
        drop(owner.await);
        drop(intake);
        drop(booted.client);
        drop(committer.await);
    });
}
