use std::rc::Rc;

use rt::sim::{Config, SimDriver};
use rt::{Runtime, spawn};
use spool::{Body, Head, HeadClear, Limits, Message, Slice, Spool};
use store::{DataFile, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 32,
    shards: 2,
};

const LIMITS: Limits = Limits {
    recipients: 100,
    inline: 1024,
    body: 512 * 1024,
    read: 1024 * 1024,
};

async fn abandon(intake: Spool, shard: u16, chunks: usize) {
    let id = intake.id(shard).await.expect("id");
    let mut writer = intake.body_stream(id, 7);
    let chunk = vec![9; intake.stream_chunk()];
    for _ in 0..chunks {
        writer.push(&chunk).await.expect("push");
    }
}

async fn accept(intake: &Spool, shard: u16) {
    let id = intake.id(shard).await.expect("id");
    let message = Message {
        id,
        tenant: 7,
        head: Head {
            clear: HeadClear {
                recipients: 1,
                ..HeadClear::default()
            },
            expiry: 9,
            wrap: [3; spool::WRAP],
            sealed: vec![1; 100],
        },
        body: Body::Inline(vec![3; 10]),
        slices: vec![Slice {
            queues: vec![4],
            sealed: vec![2; 8],
        }],
    };
    intake.accept(vec![message]).await.expect("accept");
}

#[test]
fn chunks_of_messages_never_accepted_are_reclaimed() {
    let setup = Rc::new(SimDriver::new(3, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(3, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(async {
        let setup = Setup {
            cores: 1,
            credits: 4,
            reserve: 0,
            flush: 0,
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
        let capacity = OPTIONS.region_count as usize * 2;
        for round in 0..2 * capacity {
            let first = spawn(abandon(intake.clone(), 0, 1 + round % 3));
            let second = spawn(abandon(intake.clone(), 1, 3 - round % 3));
            first.await;
            second.await;
            accept(&intake, 0).await;
            booted.client.checkpoint().await.expect("checkpoint");
        }
        intake.changes().close();
        drop(owner.await);
        drop(intake);
        drop(booted.client);
        drop(committer.await);
    });
}
