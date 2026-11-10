use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use crypto::{DataKey, DkimAlg, DkimKey, dkim_label};

pub(crate) enum Job {
    New {
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        seal: DataKey,
    },
    Load {
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        blob: Arc<[u8]>,
        seal: DataKey,
    },
    Sign {
        key: Arc<DkimKey>,
        digest: [u8; 32],
    },
}

pub(crate) enum Done {
    New(Option<(Arc<DkimKey>, Vec<u8>, Vec<u8>)>),
    Loaded(Option<Arc<DkimKey>>),
    Signed(Option<Vec<u8>>),
}

fn work(job: Job) -> Done {
    match job {
        Job::New {
            tenant,
            generation,
            key,
            alg,
            seal,
        } => Done::New((|| {
            let made = DkimKey::generate(alg).ok()?;
            let label = dkim_label(tenant, generation, key, alg);
            let blob = made.seal(&seal, &label).ok()?;
            let public = made.public().ok()?;
            Some((Arc::new(made), public, blob))
        })()),
        Job::Load {
            tenant,
            generation,
            key,
            alg,
            blob,
            seal,
        } => {
            let label = dkim_label(tenant, generation, key, alg);
            Done::Loaded(DkimKey::open(alg, &seal, &label, &blob).ok().map(Arc::new))
        }
        Job::Sign { key, digest } => Done::Signed(key.sign(&digest).ok()),
    }
}

type Task = (Job, Box<dyn FnOnce(Done) + Send>);

pub struct Signers {
    threads: usize,
    queue: Option<mpsc::Sender<Task>>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Signers {
    pub fn new(threads: usize) -> Self {
        if threads == 0 {
            return Self {
                threads,
                queue: None,
                workers: Vec::new(),
            };
        }
        let (queue, tasks) = mpsc::channel::<Task>();
        let tasks = Arc::new(Mutex::new(tasks));
        let workers = (0..threads)
            .map(|_| {
                let tasks = Arc::clone(&tasks);
                thread::spawn(move || {
                    loop {
                        let task = match tasks.lock() {
                            Ok(tasks) => tasks.recv(),
                            Err(_) => return,
                        };
                        let Ok((job, done)) = task else {
                            return;
                        };
                        done(work(job));
                    }
                })
            })
            .collect();
        Self {
            threads,
            queue: Some(queue),
            workers,
        }
    }

    pub fn limit(&self) -> usize {
        4 * self.threads.max(1)
    }

    pub(crate) fn submit(&self, job: Job, done: impl FnOnce(Done) + Send + 'static) {
        match &self.queue {
            Some(queue) => {
                if let Err(mpsc::SendError((job, done))) = queue.send((job, Box::new(done))) {
                    done(work(job));
                }
            }
            None => done(work(job)),
        }
    }
}

impl Drop for Signers {
    fn drop(&mut self) {
        self.queue = None;
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use crypto::{DkimAlg, DkimKey};

    use super::{Done, Job, Signers};

    #[test]
    fn threads_sign_every_job_and_stop_on_drop() {
        let key = Arc::new(DkimKey::generate(DkimAlg::Ed25519Sha256).expect("key"));
        let signers = Signers::new(3);
        assert_eq!(signers.limit(), 12);
        let (sent, results) = mpsc::channel();
        for n in 0..30u8 {
            let sent = sent.clone();
            let job = Job::Sign {
                key: Arc::clone(&key),
                digest: [n; 32],
            };
            signers.submit(job, move |done| {
                let signed = match done {
                    Done::Signed(signed) => signed,
                    _ => None,
                };
                sent.send((n, signed, std::thread::current().id()))
                    .expect("send");
            });
        }
        drop(sent);
        let all: Vec<_> = results.iter().collect();
        assert_eq!(all.len(), 30);
        for (n, signed, _) in &all {
            assert_eq!(signed.as_ref(), Some(&key.sign(&[*n; 32]).expect("sign")));
        }
        let here = std::thread::current().id();
        assert!(all.iter().all(|(_, _, id)| *id != here));
        drop(signers);
        assert_eq!(Signers::new(0).limit(), 4);
    }
}
