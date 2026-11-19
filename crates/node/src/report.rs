use std::time::Duration;

use control::{Grant, State};
use intake::{Envelope, Failure, Origin, Required, Submission};
use rt::{sleep, spawn};
use sched::{CONTROL_SHARD, Node, ReportMail, Reported, Transport};

use crate::Config;
use crate::settings::Tlsrpt;

const EVERY: Duration = Duration::from_mins(1);
const WITH: &str = "LOCAL";

pub(crate) fn start<T: Transport + 'static>(node: &Node<T>, config: &Config) {
    if let Some(tlsrpt) = config.tlsrpt.clone() {
        let origin = (config.session.name.clone(), config.session.lifetime);
        drop(spawn(reports(node.clone(), tlsrpt, origin)));
    }
}

async fn reports<T: Transport + 'static>(node: Node<T>, tlsrpt: Tlsrpt, origin: (String, u64)) {
    let origin = Origin {
        node: &origin.0,
        with: WITH,
        lifetime: origin.1,
    };
    let mut turn = 0;
    while !node.sched().closed() {
        for _ in 0..EVERY.as_secs() {
            if node.sched().closed() {
                return;
            }
            sleep(Duration::from_secs(1)).await;
        }
        for mail in node.sched().transport().reports().await {
            turn += 1;
            let done = submit(&node, &tlsrpt, (&origin, turn), &mail).await;
            node.sched()
                .transport()
                .reported(mail.day, &mail.domain, done);
        }
    }
}

pub async fn submit<T: Transport + 'static>(
    node: &Node<T>,
    tlsrpt: &Tlsrpt,
    (origin, turn): (&Origin<'_>, usize),
    mail: &ReportMail,
) -> Reported {
    let tenant = node.table().tenant(tlsrpt.tenant).cloned();
    let Some(tenant) = tenant.filter(|tenant| tenant.state == State::Active) else {
        return Reported::Dropped;
    };
    let Ok(mut draft) = node.draft(tenant.id, Some(tenant.default_pool)) else {
        return Reported::Failed;
    };
    let addresses: Vec<&str> = mail.to.iter().map(String::as_str).collect();
    let results = node.recipients(&mut draft, &addresses).await;
    let mut accepted = Vec::new();
    let mut temporary = false;
    for (address, result) in addresses.iter().zip(results) {
        match result {
            Ok(_) => accepted.push((*address).to_owned()),
            Err(sched::Refusal::Address | sched::Refusal::Suppressed) => {}
            Err(_) => temporary = true,
        }
    }
    if accepted.is_empty() {
        return if temporary {
            Reported::Failed
        } else {
            Reported::Dropped
        };
    }
    let shards = node.spool().shards();
    let data: Vec<u16> = shards
        .iter()
        .copied()
        .filter(|&shard| shard != CONTROL_SHARD)
        .collect();
    let pick = if data.is_empty() { &shards } else { &data };
    let Some(&shard) = pick.get(turn % pick.len().max(1)) else {
        return Reported::Failed;
    };
    let grant = Grant {
        access: 0,
        tenant: tenant.id,
        generation: draft.generation(),
        pool: tenant.default_pool,
    };
    let finished = async {
        let mut submission = Submission::open(node, &mut draft, shard).await?;
        submission.push(node, grant, &mail.message).await?;
        let envelope = Envelope {
            sender: mail.from.clone(),
            required: Required::report(),
            ..Envelope::default()
        };
        submission
            .finish(node, grant, origin, draft, envelope, &accepted)
            .await
    };
    match finished.await {
        Ok(_) => Reported::Sent,
        Err(Failure::Header(_) | Failure::FromDomain | Failure::NoKey | Failure::TooBig) => {
            Reported::Dropped
        }
        Err(Failure::Refused(_) | Failure::Temporary) => Reported::Failed,
    }
}
