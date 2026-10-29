use std::panic;
use std::path::Path;
use std::rc::Rc;
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};

use rt::{Native, Runtime};

use crate::boot::{Booted, Core, Setup, Start, boot};
use crate::committer::Committer;
use crate::error::Error;

pub fn launch<F, Fut>(path: impl AsRef<Path>, setup: Setup, work: F) -> Result<Committer, Error>
where
    F: Fn(Core) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let runtime = Runtime::new(Rc::new(Native::new()?));
    let path = path.as_ref().to_path_buf();
    let Booted {
        committer,
        client,
        starts,
    } = runtime.block_on(async move { boot(path, setup).await })?;
    drop(client);
    let work = Arc::new(work);
    let (opened, reports) = mpsc::channel();
    let mut threads = Vec::with_capacity(starts.len());
    let mut gates = Vec::with_capacity(starts.len());
    let mut failure = None;
    for start in starts {
        let (gate, wait) = mpsc::channel();
        match spawn_core(start, Arc::clone(&work), opened.clone(), wait) {
            Ok(handle) => {
                threads.push(handle);
                gates.push(gate);
            }
            Err(e) => {
                failure = Some(e);
                break;
            }
        }
    }
    drop(opened);
    let mut ready = 0;
    for report in &reports {
        match report {
            Ok(()) => ready += 1,
            Err(e) => {
                failure.get_or_insert(e);
            }
        }
    }
    if ready < threads.len() {
        failure.get_or_insert(Error::Failed);
    }
    let result = if let Some(e) = failure {
        drop(gates);
        drop(committer);
        Err(e)
    } else {
        for gate in gates {
            let _ = gate.send(());
        }
        Ok(runtime.block_on(committer.run()))
    };
    for handle in threads {
        if let Err(payload) = handle.join() {
            panic::resume_unwind(payload);
        }
    }
    result
}

fn spawn_core<F, Fut>(
    start: Start,
    work: Arc<F>,
    opened: mpsc::Sender<Result<(), Error>>,
    wait: mpsc::Receiver<()>,
) -> Result<JoinHandle<()>, Error>
where
    F: Fn(Core) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let name = format!("core-{}", start.index());
    let handle = thread::Builder::new().name(name).spawn(move || {
        let driver = match Native::new() {
            Ok(driver) => driver,
            Err(e) => {
                let _ = opened.send(Err(e.into()));
                return;
            }
        };
        Runtime::new(Rc::new(driver)).block_on(async move {
            let core = match start.open().await {
                Ok(core) => core,
                Err(e) => {
                    let _ = opened.send(Err(e));
                    return;
                }
            };
            let _ = opened.send(Ok(()));
            drop(opened);
            if wait.recv().is_ok() {
                work(core).await;
            }
        });
    })?;
    Ok(handle)
}
