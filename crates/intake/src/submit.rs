use control::Grant;
use crypto::{DkimAlg, Ids, Sealer, TAG};
use dkim::BodyHash;
use sched::{Draft, Envelope, Node, Recipient, Refusal, Sealing, Ticket, Transport, encode_slice};
use spool::{Body, BodyWriter, HeadClear, Message, SLICE};

use crate::assemble::{Signer, Stamp, assemble};
use crate::header::{Checked, Fault, HeaderBuffer, check};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Header(Fault),
    FromDomain,
    NoKey,
    Refused(Refusal),
    TooBig,
    Temporary,
}

pub struct Origin<'a> {
    pub node: &'a str,
    pub with: &'a str,
    pub lifetime: u64,
}

pub struct Submission {
    sealing: Sealing,
    id: String,
    header: HeaderBuffer,
    ready: Option<Ready>,
    hash: BodyHash,
    eight_bit: bool,
    size: u64,
    pending: Vec<u8>,
    stream: Option<(Sealer, BodyWriter)>,
    ticket: Option<Ticket>,
}

struct Ready {
    checked: Checked,
    keys: Vec<Key>,
}

struct Key {
    id: u32,
    alg: DkimAlg,
    domain: String,
    selector: String,
}

impl Submission {
    pub async fn open<T: Transport + 'static>(
        node: &Node<T>,
        draft: &mut Draft,
        shard: u16,
    ) -> Result<Self, Failure> {
        let sealing = node.sealing(draft, shard).await.map_err(Failure::Refused)?;
        let ids = node.ids().ok_or(Failure::Temporary)?;
        let ids = Ids::new(&ids).map_err(|_| Failure::Temporary)?;
        Ok(Self {
            id: ids.encode(&sealing.id().bytes()),
            sealing,
            header: HeaderBuffer::default(),
            ready: None,
            hash: BodyHash::new(),
            eight_bit: false,
            size: 0,
            pending: Vec::new(),
            stream: None,
            ticket: None,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn once(&mut self, ticket: Ticket) {
        self.ticket = Some(ticket);
    }

    pub fn discard(&mut self) {
        self.stream = None;
        self.pending = Vec::new();
    }

    pub async fn push<T: Transport + 'static>(
        &mut self,
        node: &Node<T>,
        grant: Grant,
        bytes: &[u8],
    ) -> Result<(), Failure> {
        let rest = self.header.push(bytes).map_err(Failure::Header)?;
        if self.header.done() && self.ready.is_none() {
            self.ready = Some(ready(node, grant, self.header.section())?);
        }
        if rest.is_empty() {
            return Ok(());
        }
        self.eight_bit |= rest.iter().any(|&b| b >= 0x80);
        self.hash.update(rest);
        self.size += rest.len() as u64;
        self.pending.extend_from_slice(rest);
        let spool = node.spool();
        let inline = spool.limits().inline.saturating_sub(TAG);
        if self.stream.is_none() && self.pending.len() > inline {
            let sealer = self.sealing.body_chunks().map_err(Failure::Refused)?;
            let writer = spool.body_stream(self.sealing.id(), grant.tenant);
            self.stream = Some((sealer, writer));
        }
        let plain = spool.stream_chunk() - TAG;
        if let Some((sealer, writer)) = self.stream.as_mut() {
            while self.pending.len() > plain {
                let mut chunk: Vec<u8> = self.pending.drain(..plain).collect();
                sealer.seal(&mut chunk).map_err(|_| Failure::Temporary)?;
                writer.push(&chunk).await.map_err(|e| spool_error(&e))?;
            }
        }
        Ok(())
    }

    pub async fn finish<T: Transport + 'static>(
        mut self,
        node: &Node<T>,
        grant: Grant,
        origin: &Origin<'_>,
        draft: Draft,
        envelope: Envelope,
        recipients: &[String],
    ) -> Result<String, Failure> {
        let ready = match self.ready.take() {
            Some(ready) => ready,
            None => ready(node, grant, self.header.section())?,
        };
        let body = match self.stream.take() {
            None => self
                .sealing
                .inline_body(&self.pending)
                .map_err(Failure::Refused)?,
            Some((sealer, mut writer)) => {
                let mut last = std::mem::take(&mut self.pending);
                sealer.seal_last(&mut last);
                writer.push(&last).await.map_err(|e| spool_error(&e))?;
                Body::Chain(writer.finish().map_err(|e| spool_error(&e))?)
            }
        };
        let accepted = node.sched().clock().now();
        let signers: Vec<Signer> = ready
            .keys
            .iter()
            .map(|key| Signer {
                key: key.id,
                alg: key.alg,
                domain: &key.domain,
                selector: &key.selector,
            })
            .collect();
        let stamp = Stamp {
            node: origin.node,
            with: origin.with,
            id: &self.id,
            now: accepted,
            lifetime: origin.lifetime,
        };
        let section = assemble(
            self.header.section(),
            &ready.checked,
            &stamp,
            &signers,
            &self.hash.finish(),
        )
        .map_err(Failure::Header)?;
        let envelope = Envelope {
            eight_bit: self.eight_bit,
            signatures: ready.keys.iter().map(|key| (key.id, key.alg)).collect(),
            ..envelope
        }
        .encode()
        .ok_or(Failure::Temporary)?;
        let count = u32::try_from(recipients.len()).map_err(|_| Failure::Temporary)?;
        let clear = HeadClear {
            recipients: count,
            body_size: self.size,
            accepted,
            ..HeadClear::default()
        };
        let head = self
            .sealing
            .head(clear, accepted + origin.lifetime, &envelope, &section)
            .map_err(Failure::Refused)?;
        let mut slices = Vec::new();
        let groups = draft.queues().chunks(SLICE as usize);
        for (n, (queues, addresses)) in (0u32..).zip(groups.zip(recipients.chunks(SLICE as usize)))
        {
            let recipients: Vec<Recipient> = addresses
                .iter()
                .map(|address| Recipient {
                    address: address.clone(),
                    ..Recipient::default()
                })
                .collect();
            let plain = encode_slice(&recipients).ok_or(Failure::Temporary)?;
            slices.push(
                self.sealing
                    .slice(n, queues.to_vec(), &plain)
                    .map_err(Failure::Refused)?,
            );
        }
        let message = Message {
            id: self.sealing.id(),
            tenant: draft.tenant(),
            head,
            body,
            slices,
        };
        let accepted = match self.ticket.take() {
            Some(ticket) => node.accept_once(ticket, draft, message).await,
            None => node.accept(draft, message).await,
        };
        accepted.map_err(Failure::Refused)?;
        Ok(self.id)
    }
}

fn ready<T: Transport + 'static>(
    node: &Node<T>,
    grant: Grant,
    section: &[u8],
) -> Result<Ready, Failure> {
    let checked = check(section).map_err(Failure::Header)?;
    let table = node.table();
    let domain = table
        .sender(grant.tenant, &checked.from)
        .ok_or(Failure::FromDomain)?;
    let keys: Vec<Key> = [domain.rsa, domain.ed25519]
        .into_iter()
        .filter(|&id| id != 0)
        .filter_map(|id| table.dkim(grant.tenant, id))
        .filter(|dkim| dkim.generation == grant.generation)
        .map(|dkim| Key {
            id: dkim.id,
            alg: dkim.alg,
            domain: dkim.domain.to_string(),
            selector: dkim.selector.to_string(),
        })
        .collect();
    if keys.is_empty() {
        return Err(Failure::NoKey);
    }
    Ok(Ready { checked, keys })
}

fn spool_error(error: &spool::Error) -> Failure {
    match error {
        spool::Error::Limit("body" | "chunk" | "inline body") => Failure::TooBig,
        _ => Failure::Temporary,
    }
}
