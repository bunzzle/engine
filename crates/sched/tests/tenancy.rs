use std::rc::Rc;
use std::sync::Arc;

use control::Tenancy;
use rt::sim::{Config, SimDriver};
use rt::{Mesh, Runtime, spawn, yield_now};
use sched::{Answered, Arrival, Attempt, Clock, Note, Sched, Transport};
use spool::{MessageId, Spool};
use store::{DataFile, Options, SLOT_SIZE, Setup, boot};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 32,
    shards: 2,
};

const LIMITS: spool::Limits = spool::Limits {
    recipients: 3000,
    inline: 2048,
    body: 512 * 1024,
};

struct Held;

impl Tenancy for Held {
    fn holder(&self, queue: u32) -> Option<(u32, u32)> {
        (queue == 10).then_some((1, 4))
    }
}

struct Idle;

impl Transport for Idle {
    fn send(&self, _: Attempt) -> impl Future<Output = Vec<Answered>> {
        std::future::ready(Vec::new())
    }
}

#[test]
fn enqueue_with_another_tenant_or_generation_is_refused() {
    let driver = Rc::new(SimDriver::new(1, Config::default()));
    Runtime::new(driver).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
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
        let (spool, owner, _) = Spool::open(core, 1, LIMITS).await.expect("spool");
        let owner = spawn(owner.run());
        let mesh = Arc::new(Mesh::<Note>::new(1));
        let ends = mesh.take(0).expect("ends");
        let clock = Clock::start();
        let (sched, done) = Sched::start(
            ends,
            spool.clone(),
            Idle,
            Rc::new(Held),
            clock,
            sched::Config::new(2),
        );
        let arrival = |tenant, generation, queue| Arrival {
            id: MessageId {
                node: 1,
                shard: 0,
                key: 7,
            },
            tenant,
            generation,
            due: u64::MAX / 2,
            queues: vec![queue],
        };
        for (tenant, generation, queue) in [(2, 4, 10), (1, 3, 10), (1, 4, 11), (1, 4, 10)] {
            sched.enqueue(arrival(tenant, generation, queue));
        }
        for _ in 0..10 {
            yield_now().await;
        }
        assert_eq!(sched.refused(), 3);
        assert_eq!(sched.queued(), 1);
        sched.close();
        done.await;
        drop(sched);
        spool.changes().close();
        drop(owner.await);
        drop(spool);
        drop(booted.client);
        committer.await;
    });
}
