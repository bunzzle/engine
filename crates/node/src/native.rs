use std::path::Path;
use std::process;
use std::rc::Rc;
use std::sync::Arc;

use crypto::Secret;
use deliver::Deliver;
use dns::Resolver;
use rt::{Mesh, Native, Runtime};
use sched::Transport;
use store::Setup;
use tls::{Certs, Connector};

use crate::{Config, Error, Plan, load, naming, run};

pub fn serve<T, F>(path: &Path, transport: F) -> Result<(), Error>
where
    T: Transport + 'static,
    F: Fn(u16) -> Result<T, String> + Send + Sync + 'static,
{
    let (config, certs, roots) = load(path).map_err(Error::Config)?;
    launch(config, certs, roots, transport)
}

pub fn deliver(path: &Path) -> Result<(), Error> {
    let (config, certs, roots) = load(path).map_err(Error::Config)?;
    let mesh = Mesh::new(config.cores);
    let reports = Mesh::new(config.cores);
    let key = *Secret::<16>::random().map_err(|_| Error::Random)?.expose();
    let dns = config.dns.clone();
    let delivery = config.delivery.clone();
    let pem = roots.clone();
    launch(config, certs, pem, move |core| {
        let ends = mesh.take(core).ok_or("delivery mesh already taken")?;
        let (leases, limits) = deliver::limits(ends, delivery.connections, key);
        drop(limits);
        let seed = Secret::<32>::random().map_err(|_| "no random source")?;
        let resolver = Resolver::new(dns.clone(), &seed);
        let connector =
            Connector::new(tls::provider(), roots.as_deref()).map_err(|e| e.to_string())?;
        let turn = Secret::<8>::random().map_err(|_| "no random source")?;
        let mut deliver = Deliver::new(
            resolver,
            connector,
            delivery.settings.clone(),
            Some(leases),
            u64::from_le_bytes(*turn.expose()),
        )
        .map_err(|_| String::from("`ehlo` cannot be sent"))?;
        let ends = reports.take(core).ok_or("report mesh already taken")?;
        drop(deliver.report_mesh(ends));
        Ok(deliver)
    })
}

fn launch<T, F>(
    config: Config,
    certs: Certs,
    roots: Option<Vec<u8>>,
    transport: F,
) -> Result<(), Error>
where
    T: Transport + 'static,
    F: Fn(u16) -> Result<T, String> + Send + Sync + 'static,
{
    sys::process::private_umask();
    sys::process::no_core_dumps().map_err(Error::Io)?;
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
    )
    .with_roots(roots);
    let plan = Arc::new(plan);
    let committer = store::launch(store, setup, move |core| {
        let plan = Arc::clone(&plan);
        let transport = transport(core.index);
        async move {
            let result = match transport {
                Ok(transport) => run(core, plan, transport).await,
                Err(e) => Err(Error::Config(e)),
            };
            if let Err(e) = result {
                eprintln!("bunzzle: {e}");
                process::exit(1);
            }
        }
    })
    .map_err(Error::Store)?;
    drop(committer);
    Ok(())
}
