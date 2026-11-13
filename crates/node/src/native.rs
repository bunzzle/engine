use std::path::Path;
use std::process;
use std::rc::Rc;
use std::sync::Arc;

use crypto::Secret;
use rt::{Native, Runtime};
use sched::Transport;
use store::Setup;

use crate::{Error, Plan, load, naming, run};

pub fn serve<T, F>(path: &Path, transport: F) -> Result<(), Error>
where
    T: Transport + 'static,
    F: Fn(u16) -> T + Send + Sync + 'static,
{
    sys::process::private_umask();
    sys::process::no_core_dumps().map_err(Error::Io)?;
    let (config, certs) = load(path).map_err(Error::Config)?;
    let runtime = Runtime::new(Rc::new(Native::new().map_err(Error::Io)?));
    let probe = config.clone();
    let naming = runtime.block_on(async move { naming(&probe).await })?;
    drop(runtime);
    let guard = Secret::<16>::random().map_err(|_| Error::Random)?;
    let setup = Setup {
        cores: config.cores,
        credits: config.store.credits,
        reserve: config.store.reserve,
        flush: config.store.flush,
    };
    let store = config.store.path.clone();
    let plan = Plan::new(
        config,
        Arc::new(certs),
        tls::provider(),
        naming,
        *guard.expose(),
    );
    let plan = Arc::new(plan);
    let committer = store::launch(store, setup, move |core| {
        let plan = Arc::clone(&plan);
        let transport = transport(core.index);
        async move {
            if let Err(e) = run(core, plan, transport).await {
                eprintln!("bunzzle: {e}");
                process::exit(1);
            }
        }
    })
    .map_err(Error::Store)?;
    drop(committer);
    Ok(())
}
