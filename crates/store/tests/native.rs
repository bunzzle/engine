#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::rc::Rc;
use std::{fs, process};

use rt::{Buf, Native, Runtime, spawn};
use store::{
    Claim, Committer, DataFile, Options, Record, SLOT_SIZE, Submission, Write, load, recover,
};

const OPTIONS: Options = Options {
    journal_size: 16 * SLOT_SIZE,
    region_size: 2 * SLOT_SIZE,
    region_count: 8,
    shards: 4,
};

fn run<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    let driver = Rc::new(Native::new().expect("native driver"));
    Runtime::new(driver).block_on(future)
}

#[test]
fn the_store_works_on_a_real_disk() {
    let dir = std::env::temp_dir().join(format!("store-native-{}", process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    let path: PathBuf = dir.join("store");
    let target = path.clone();
    let locations = run(async move {
        DataFile::create(&target, &OPTIONS).await.expect("create");
        let data = DataFile::open(&target).await.expect("open");
        let loaded = load(&data, 0).await.expect("load");
        let recovered = recover(&data, loaded.position, loaded.state)
            .await
            .expect("recover");
        let (committer, client) = Committer::new(data, recovered.journal, recovered.state);
        let committer = spawn(committer.run());
        let mut locations = Vec::new();
        for step in 0..20u8 {
            let durable = client
                .commit(Submission {
                    claim: Claim::Intake,
                    records: vec![Write {
                        kind: 7,
                        tenant: 3,
                        payload: vec![step; 100 + usize::from(step) * 10],
                    }],
                    bodies: Vec::new(),
                    dead: Vec::new(),
                })
                .await
                .expect("commit");
            locations.push(durable.locations[0]);
            if step == 10 {
                client.checkpoint().await.expect("checkpoint");
            }
        }
        drop(client);
        drop(committer.await);
        locations
    });
    run(async move {
        let data = DataFile::open(&path).await.expect("reopen");
        let loaded = load(&data, 0).await.expect("load");
        let recovered = recover(&data, loaded.position, loaded.state)
            .await
            .expect("recover");
        assert_eq!(recovered.torn, None);
        for (step, location) in (0u8..).zip(&locations) {
            let offset = data.region_offset(location.region) + location.offset;
            let len = location.size as usize;
            let (read, buf) = data.file().read_at(Buf::new(len), offset).await;
            assert_eq!(read.expect("read"), len);
            let record = Record::decode(&buf).expect("decode");
            assert_eq!(
                record.payload(),
                &vec![step; 100 + usize::from(step) * 10][..]
            );
        }
    });
    fs::remove_dir_all(dir).expect("clean up");
}
