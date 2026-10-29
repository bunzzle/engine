use std::rc::Rc;
use std::time::Duration;

use rt::sim::{Config, SimDriver};
use rt::{Buf, File, JoinHandle, OpenOptions, Runtime, now, sleep, spawn};
use store::{
    Body, Claim, Client, Committer, DataFile, Dead, Error, Event, Location, Options, Part, Range,
    Results, SLOT_SIZE, Session, Submission, Write, ZONE_SIZE, checksum, load, recover,
};

const PATH: &str = "/data/store";

const OPTIONS: Options = Options {
    journal_size: 4 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 16,
    shards: 4,
};

fn run<T: 'static>(seed: u64, future: impl Future<Output = T> + 'static) -> T {
    let setup = Rc::new(SimDriver::new(seed, Config::default()));
    Runtime::new(setup.clone()).block_on(async {
        DataFile::create(PATH, &OPTIONS).await.expect("create");
    });
    let driver = Rc::new(SimDriver::with_disk(seed, Config::default(), setup.crash()));
    Runtime::new(driver).block_on(future)
}

async fn start(
    sessions: u32,
    credits: u32,
    part_timeout: Duration,
) -> (Client, Vec<(Session, Results)>, JoinHandle<Committer>) {
    let data = DataFile::open(PATH).await.expect("open");
    let loaded = load(&data, 0).await.expect("load");
    let recovered = recover(&data, loaded.position, loaded.state)
        .await
        .expect("recover");
    let (mut committer, client) = Committer::new(data, recovered.journal, recovered.state);
    committer.set_part_timeout(part_timeout);
    let sessions = (0..sessions)
        .map(|_| committer.session(&client, credits))
        .collect();
    (client, sessions, spawn(committer.run()))
}

fn submission(shard: u16, byte: u8) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: vec![Write {
            kind: 7,
            shard,
            tenant: 1,
            payload: vec![byte; 64],
        }],
        bodies: Vec::new(),
        dead: Vec::new(),
    }
}

fn part(tag: u16, sequence: u64) -> Part {
    Part {
        tag,
        replay_sequence: sequence,
        bytes: Vec::new(),
    }
}

#[test]
fn results_arrive_in_commit_order_and_return_credits() {
    run(1, async {
        let (_client, mut sessions, _committer) = start(1, 4, Duration::from_secs(1)).await;
        let (session, mut results) = sessions.remove(0);
        let mut tags = Vec::new();
        let mut sequences = Vec::new();
        for round in 0..5u64 {
            for i in 0..4u64 {
                session
                    .submit(round * 4 + i, submission(0, 1))
                    .expect("credit");
            }
            assert!(matches!(
                session.submit(99, submission(0, 1)),
                Err(Error::Busy)
            ));
            for _ in 0..4 {
                match results.recv().await {
                    Some(Event::Durable { tag, sequence, .. }) => {
                        tags.push(tag);
                        sequences.push(sequence);
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            assert_eq!(session.credits(), 4);
        }
        assert_eq!(tags, (0..20).collect::<Vec<u64>>());
        assert!(sequences.windows(2).all(|w| w[0] <= w[1]));
    });
}

#[test]
fn rejected_submissions_come_back_with_their_tag() {
    run(2, async {
        let (_client, mut sessions, _committer) = start(1, 2, Duration::from_secs(1)).await;
        let (session, mut results) = sessions.remove(0);
        session.submit(7, submission(9, 1)).expect("credit");
        match results.recv().await {
            Some(Event::Rejected { tag, error }) => {
                assert_eq!(tag, 7);
                assert!(matches!(error, Error::Invalid("shard")));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(session.credits(), 2);
    });
}

fn answer_cuts(
    session: Session,
    mut results: Results,
    tag: u16,
    valid: bool,
) -> JoinHandle<Vec<Event>> {
    spawn(async move {
        let mut seen = Vec::new();
        while let Some(event) = results.recv().await {
            if let Event::Cut { sequence } = event {
                let replay = if valid { sequence } else { sequence + 1 };
                session
                    .parts(sequence, vec![part(tag, replay)])
                    .expect("send parts");
            }
            let done = matches!(event, Event::Published { .. } | Event::Abandoned { .. });
            seen.push(event);
            if done {
                return seen;
            }
        }
        seen
    })
}

#[test]
fn a_checkpoint_collects_one_answer_per_session() {
    run(3, async {
        let (client, sessions, committer) = start(2, 2, Duration::from_secs(1)).await;
        let mut answers = Vec::new();
        for (tag, (session, results)) in (0u16..).zip(sessions) {
            session.submit(1, submission(tag, 3)).expect("credit");
            answers.push(answer_cuts(session, results, tag, true));
        }
        let cut = client.checkpoint().await.expect("checkpoint");
        for answer in answers {
            let events = answer.await;
            assert!(
                matches!(events.last(), Some(Event::Published { sequence }) if *sequence == cut)
            );
            let at = events
                .iter()
                .position(|e| matches!(e, Event::Cut { .. }))
                .expect("cut");
            assert!(
                events[..at]
                    .iter()
                    .all(|e| matches!(e, Event::Durable { sequence, .. } if *sequence < cut))
            );
        }
        drop(client);
        drop(committer.await);
        let data = DataFile::open(PATH).await.expect("reopen");
        let loaded = load(&data, 0).await.expect("load");
        let mut tags: Vec<u16> = loaded.parts.iter().map(|p| p.tag).collect();
        tags.sort_unstable();
        assert_eq!(tags, vec![0, 1]);
        assert!(loaded.parts.iter().all(|p| p.replay_sequence == cut));
    });
}

#[test]
fn a_bad_part_abandons_the_checkpoint() {
    run(4, async {
        let (client, mut sessions, _committer) = start(1, 2, Duration::from_secs(1)).await;
        let (session, results) = sessions.remove(0);
        let answer = answer_cuts(session, results, 0, false);
        let result = client.checkpoint().await;
        assert!(matches!(result, Err(Error::Invalid("part"))));
        let events = answer.await;
        assert!(matches!(events.last(), Some(Event::Abandoned { .. })));
        client
            .checkpoint()
            .await
            .expect("a session that is gone is not waited for");
    });
}

#[test]
fn a_dropped_session_is_not_waited_for() {
    run(5, async {
        let (client, mut sessions, _committer) = start(2, 2, Duration::from_secs(1)).await;
        let (kept, results) = sessions.remove(0);
        drop(sessions);
        let answer = answer_cuts(kept, results, 0, true);
        client.checkpoint().await.expect("checkpoint");
        assert!(matches!(answer.await.last(), Some(Event::Published { .. })));
    });
}

#[test]
#[should_panic(expected = "checkpoint part missing")]
fn a_missing_part_stops_the_process() {
    run(6, async {
        let (client, sessions, _committer) = start(1, 2, Duration::from_millis(5)).await;
        let _silent = sessions;
        let _ = client.checkpoint().await;
    });
}

fn answer_late(
    session: Session,
    mut results: Results,
    delay: Duration,
    stop_after: u32,
) -> JoinHandle<u32> {
    spawn(async move {
        let mut published = 0;
        while published < stop_after
            && let Some(event) = results.recv().await
        {
            match event {
                Event::Cut { sequence } => {
                    sleep(delay).await;
                    session
                        .parts(sequence, vec![part(0, sequence)])
                        .expect("send parts");
                }
                Event::Published { .. } => published += 1,
                _ => {}
            }
        }
        published
    })
}

#[test]
fn commits_continue_while_parts_are_collected() {
    run(7, async {
        let (client, mut sessions, committer) = start(1, 2, Duration::from_secs(5)).await;
        let (session, results) = sessions.remove(0);
        let answers = answer_late(session, results, Duration::from_millis(50), 1);
        let checkpoint = {
            let client = client.clone();
            spawn(async move { client.checkpoint().await })
        };
        sleep(Duration::from_millis(1)).await;
        let started = now();
        let durable = client.commit(submission(1, 9)).await.expect("commit");
        assert!(now().saturating_duration_since(started) < Duration::from_millis(50));
        let cut = checkpoint.await.expect("checkpoint");
        assert!(durable.sequence >= cut);
        drop(client);
        drop(committer.await);
        assert_eq!(answers.await, 1);
        let data = DataFile::open(PATH).await.expect("reopen");
        let loaded = load(&data, 0).await.expect("load");
        assert_eq!(loaded.position.sequence, cut);
        let recovered = recover(&data, loaded.position, loaded.state)
            .await
            .expect("recover");
        assert_eq!(recovered.torn, None);
        assert!(recovered.journal.position().sequence > durable.sequence);
    });
}

#[test]
fn a_full_journal_waits_for_the_checkpoint_in_flight() {
    run(8, async {
        let (client, mut sessions, committer) = start(1, 2, Duration::from_secs(5)).await;
        let (session, results) = sessions.remove(0);
        let answers = answer_late(session, results, Duration::from_secs(2), 2);
        let mut previous: Option<Location> = None;
        for step in 0..300u32 {
            let mut next = submission(0, u8::try_from(step % 251).expect("fits"));
            if let Some(location) = previous {
                next.dead.push(Dead {
                    tenant: 1,
                    region: location.region,
                    epoch: location.epoch,
                    offset: location.offset,
                    length: location.size,
                });
            }
            let durable = client
                .commit(next)
                .await
                .unwrap_or_else(|e| panic!("commit {step}: {e}"));
            previous = Some(durable.locations[0]);
        }
        assert_eq!(
            answers.await,
            2,
            "the journal wrapped through two checkpoints"
        );
        drop(client);
        drop(committer.await);
    });
}

#[test]
fn a_region_being_released_takes_no_bodies() {
    run(9, async {
        let (client, mut sessions, _committer) = start(1, 2, Duration::from_secs(5)).await;
        let (session, results) = sessions.remove(0);
        let _answers = answer_late(session, results, Duration::from_millis(50), 1);
        let lease = client.allocate(Claim::Intake).await.expect("allocate");
        let (region, epoch) = (lease.region(), lease.epoch());
        let bytes = vec![4u8; 4096];
        write_raw(region, &bytes).await;
        let range = Range {
            region,
            epoch,
            offset: 0,
            length: 4096,
            checksum: checksum(&bytes),
        };
        client
            .commit(body(range, Vec::new()))
            .await
            .expect("commit body");
        let dead = Dead {
            tenant: 1,
            region,
            epoch,
            offset: 0,
            length: 4096,
        };
        client.commit(body_dead(dead)).await.expect("kill body");
        lease.seal();
        let checkpoint = {
            let client = client.clone();
            spawn(async move { client.checkpoint().await })
        };
        sleep(Duration::from_millis(1)).await;
        let late = client.commit(body(range, Vec::new())).await;
        assert!(matches!(late, Err(Error::Invalid("range"))));
        checkpoint.await.expect("checkpoint");
    });
}

fn body(range: Range, dead: Vec<Dead>) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: Vec::new(),
        bodies: vec![Body { tenant: 1, range }],
        dead,
    }
}

fn body_dead(dead: Dead) -> Submission {
    Submission {
        claim: Claim::Intake,
        records: Vec::new(),
        bodies: Vec::new(),
        dead: vec![dead],
    }
}

async fn write_raw(region: u32, bytes: &[u8]) {
    let options = OpenOptions {
        read: true,
        write: true,
        ..OpenOptions::default()
    };
    let file = File::open(PATH, &options).await.expect("open raw");
    let at = ZONE_SIZE + OPTIONS.journal_size + u64::from(region) * OPTIONS.region_size;
    let (result, _) = file.write_all_at(Buf::from_slice(bytes), at).await;
    result.expect("write raw");
}
