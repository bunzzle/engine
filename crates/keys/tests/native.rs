use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::rc::Rc;

use crypto::DkimAlg;
use keys::proto::{Answer, Request};
use keys::{Audit, Client, Error, Server, Settings, Vault};
use rt::{Native, Runtime, UnixListener, spawn};

const DAY: u32 = 20_833;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("keys-native-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

async fn call(client: &Client, request: Request) -> Answer {
    client.call(&request).await.expect("call")
}

fn sign(tenant: u32, n: u8) -> Request {
    Request::Sign {
        tenant,
        generation: 1,
        key: 1,
        alg: DkimAlg::Ed25519Sha256,
        digest: [n; 32],
    }
}

#[test]
fn the_signing_threads_answer_every_sign_across_a_delete() {
    let dir = scratch("signers");
    let path = dir.clone();
    let uid = fs::metadata(&dir).expect("dir").uid();
    let driver = Native::new().expect("driver");
    Runtime::new(Rc::new(driver)).block_on(async move {
        let vault = Vault::init(&path, DAY).await.expect("init");
        let audit = Audit::open(&path).await.expect("audit");
        let settings = Settings {
            signers: 2,
            ..Settings::default()
        };
        let server = Server::start(vault, audit, settings);
        let socket = path.join("keys.sock");
        server.listen(UnixListener::bind(&socket).await.expect("bind"), uid);
        let client = Rc::new(Client::connect(&socket, uid).await.expect("connect"));
        for tenant in [1, 2] {
            let create = Request::Create {
                tenant,
                generation: 1,
                retention: 30,
            };
            assert!(matches!(call(&client, create).await, Answer::Keys { .. }));
            let new = Request::DkimNew {
                tenant,
                generation: 1,
                key: 1,
                alg: DkimAlg::Ed25519Sha256,
            };
            assert!(matches!(call(&client, new).await, Answer::Dkim { .. }));
        }
        let mut tasks = Vec::new();
        for n in 0..40u8 {
            let signing = Rc::clone(&client);
            tasks.push(spawn(async move { call(&signing, sign(1, n)).await }));
            if n == 20 {
                let client = Rc::clone(&client);
                let delete = Request::Delete {
                    tenant: 2,
                    generation: 1,
                };
                tasks.push(spawn(async move { call(&client, delete).await }));
            }
        }
        let (mut signed, mut busy, mut deleted) = (0u64, 0, 0);
        for task in tasks {
            match task.await {
                Answer::Signature(_) => signed += 1,
                Answer::Done => deleted += 1,
                Answer::Refused(Error::Busy) => busy += 1,
                _ => panic!("unexpected answer"),
            }
        }
        assert_eq!((signed + busy, deleted), (40, 1));
        assert_eq!(server.stats().signs, signed);
        let mut tasks = Vec::new();
        for n in 0..8u8 {
            let client = Rc::clone(&client);
            tasks.push(spawn(async move { call(&client, sign(1, n)).await }));
        }
        for task in tasks {
            assert!(matches!(task.await, Answer::Signature(_)));
        }
        assert!(matches!(
            call(&client, sign(2, 0)).await,
            Answer::Refused(Error::Unknown)
        ));
    });
    fs::remove_dir_all(&dir).expect("clean");
}
