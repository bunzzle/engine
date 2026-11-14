use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use control::Table;
use crypto::{Opener as ChunkOpener, Wrap};
use spool::{Chunks, MessageId, Opened, Pinned, SLICE, Source, Stored};

use crate::dkim::{sign, signer};
use crate::envelope::{Envelope, Recipient, decode_slice};
use crate::error::Refusal;
use crate::policy::Answer;
use crate::sealing::{Keys, Opener, Unsealable, opener};
use crate::transport::{Answered, Claimed};

pub const SIGNED_KEPT: usize = 65_536;
pub const KEYS_WAIT: u64 = 30_000;
const SIGNER_GONE: &[u8] = b"550 5.7.1 Signing key removed";
const UNSIGNABLE: &[u8] = b"554 5.3.0 Stored message cannot be signed";
const UNREADABLE: &[u8] = b"554 5.3.0 Stored recipients cannot be read";

pub enum Body {
    Inline(Vec<u8>),
    Chain(Plain),
}

pub struct Plain {
    chunks: Chunks,
    opener: ChunkOpener,
    ahead: Option<Vec<u8>>,
    started: bool,
}

impl Plain {
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, Unsealable> {
        if !self.started {
            self.started = true;
            self.ahead = self.chunks.next().await.map_err(|_| Unsealable::Bad)?;
        }
        let Some(mut current) = self.ahead.take() else {
            self.opener.finish().map_err(|_| Unsealable::Bad)?;
            return Ok(None);
        };
        self.ahead = self.chunks.next().await.map_err(|_| Unsealable::Bad)?;
        let last = self.ahead.is_none();
        let len = self
            .opener
            .open(last, &mut current)
            .map_err(|_| Unsealable::Bad)?
            .len();
        current.truncate(len);
        Ok(Some(current))
    }
}

pub struct Prepared {
    pub envelope: Envelope,
    pub recipients: Vec<(u32, Recipient)>,
    header: Vec<u8>,
    pub body: Body,
    pub opener: Opener,
    _pins: Pinned,
}

impl Prepared {
    pub fn header(&self) -> &[u8] {
        &self.header
    }
}

pub enum Fault {
    Unopened {
        fault: Unsealable,
        generation: u32,
        day: u32,
    },
    Keys,
    Signer(Opener),
    Format(Opener),
    Recipients(Opener),
}

impl Fault {
    pub fn answers(&self, claimed: &[Claimed]) -> Vec<Answered> {
        let (answer, failed) = match self {
            Self::Unopened {
                fault,
                generation,
                day,
            } => (
                Answer::Unopened {
                    fault: *fault,
                    generation: *generation,
                    day: *day,
                },
                None,
            ),
            Self::Keys => (Answer::Later(KEYS_WAIT), None),
            Self::Signer(opener) => (Answer::Failed, Some((opener, SIGNER_GONE))),
            Self::Format(opener) => (Answer::Failed, Some((opener, UNSIGNABLE))),
            Self::Recipients(opener) => (Answer::Failed, Some((opener, UNREADABLE))),
        };
        claimed
            .iter()
            .map(|c| Answered {
                recipient: c.recipient,
                answer,
                reply: failed
                    .and_then(|(opener, text)| opener.seal_reply(c.recipient, c.stamp, text).ok())
                    .unwrap_or_default(),
            })
            .collect()
    }
}

pub(crate) struct Signing {
    keys: Rc<dyn Keys>,
    table: Rc<RefCell<Table>>,
    cache: RefCell<Cache>,
    unsigned: Cell<u64>,
}

impl Signing {
    pub(crate) fn new(keys: Rc<dyn Keys>, table: Rc<RefCell<Table>>) -> Self {
        Self {
            keys,
            table,
            cache: RefCell::new(Cache::default()),
            unsigned: Cell::new(0),
        }
    }

    pub(crate) fn unsigned(&self) -> u64 {
        self.unsigned.get()
    }

    pub(crate) fn cached(&self) -> usize {
        self.cache.borrow().len()
    }
}

pub struct Outgoing {
    pub stored: Stored,
    opened: Opened,
    signing: Option<Rc<Signing>>,
    wanted: Vec<u32>,
}

impl Outgoing {
    pub(crate) fn new(
        stored: Stored,
        opened: Opened,
        signing: Option<Rc<Signing>>,
        wanted: Vec<u32>,
    ) -> Self {
        Self {
            stored,
            opened,
            signing,
            wanted,
        }
    }

    pub async fn prepare(self) -> Result<Prepared, Fault> {
        let Some(signing) = self.signing else {
            return Err(Fault::Keys);
        };
        let prepared = prepare(&signing, &self.stored, self.opened, &self.wanted).await;
        if matches!(prepared, Err(Fault::Format(_))) {
            signing.unsigned.set(signing.unsigned.get() + 1);
        }
        prepared
    }
}

#[derive(Default)]
pub(crate) struct Cache {
    signed: BTreeMap<MessageId, Rc<[Vec<u8>]>>,
    order: VecDeque<MessageId>,
}

impl Cache {
    fn get(&self, id: MessageId) -> Option<Rc<[Vec<u8>]>> {
        self.signed.get(&id).cloned()
    }

    fn put(&mut self, id: MessageId, fields: Rc<[Vec<u8>]>) {
        if self.signed.insert(id, fields).is_some() {
            return;
        }
        self.order.push_back(id);
        while self.order.len() > SIGNED_KEPT {
            if let Some(old) = self.order.pop_front() {
                self.signed.remove(&old);
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.signed.len()
    }
}

async fn prepare(
    signing: &Signing,
    stored: &Stored,
    read: Opened,
    wanted: &[u32],
) -> Result<Prepared, Fault> {
    let (keys, table, cache) = (&*signing.keys, &*signing.table, &signing.cache);
    let unopened = |fault, generation| Fault::Unopened {
        fault,
        generation,
        day: stored.clear.day,
    };
    let generation = Wrap::decode(&read.wrap)
        .map_err(|_| unopened(Unsealable::Bad, 0))?
        .generation;
    let opener = opener(
        keys,
        stored.tenant,
        generation,
        stored.id,
        &stored.clear,
        &read.wrap,
    )
    .await
    .map_err(|fault| unopened(fault, generation))?;
    let (envelope, section) = opener
        .head(&read.head)
        .map_err(|fault| unopened(fault, generation))?;
    let Some((envelope, fields)) = check(&envelope, &section) else {
        return Err(Fault::Format(opener));
    };
    let recipients = match open_recipients(&opener, &read.slices, stored.clear.recipients, wanted) {
        Ok(recipients) => recipients,
        Err(Some(fault)) => return Err(unopened(fault, generation)),
        Err(None) => return Err(Fault::Recipients(opener)),
    };
    let count = envelope.signatures.len();
    let cached = cache.borrow().get(stored.id);
    let signed = if let Some(signed) = cached {
        signed
    } else {
        let mut signed = Vec::with_capacity(count);
        for (at, (key, _)) in (1..=count).zip(&envelope.signatures) {
            let Ok(digest) = dkim::digest(&fields, at) else {
                return Err(Fault::Format(opener));
            };
            let signature = match sign(table, keys, stored.tenant, *key, digest).await {
                Ok(signature) => signature,
                Err(Refusal::Signer) => return Err(Fault::Signer(opener)),
                Err(_) => return Err(Fault::Keys),
            };
            let Ok(field) = dkim::signed(fields[at].raw(), &signature) else {
                return Err(Fault::Format(opener));
            };
            signed.push(field);
        }
        let signed: Rc<[Vec<u8>]> = signed.into();
        cache.borrow_mut().put(stored.id, Rc::clone(&signed));
        signed
    };
    for (key, _) in &envelope.signatures {
        match signer(&table.borrow(), stored.tenant, *key, |_| ()) {
            Ok(()) => {}
            Err(Refusal::Signer) => return Err(Fault::Signer(opener)),
            Err(_) => return Err(Fault::Keys),
        }
    }
    let mut header = Vec::with_capacity(section.len() + 512 * count);
    header.extend_from_slice(fields[0].raw());
    for field in signed.iter() {
        header.extend_from_slice(field);
    }
    for field in &fields[count + 1..] {
        header.extend_from_slice(field.raw());
    }
    let body = match read.body {
        Source::Inline(sealed) => Body::Inline(
            opener
                .inline_body(&sealed)
                .map_err(|fault| unopened(fault, generation))?,
        ),
        Source::Chain(chunks) => Body::Chain(Plain {
            chunks,
            opener: opener.body_chunks(),
            ahead: None,
            started: false,
        }),
    };
    Ok(Prepared {
        envelope,
        recipients,
        header,
        body,
        opener,
        _pins: read.pins,
    })
}

fn open_recipients(
    opener: &Opener,
    sealed: &[(u32, Vec<u8>)],
    total: u32,
    wanted: &[u32],
) -> Result<Vec<(u32, Recipient)>, Option<Unsealable>> {
    let mut slices = BTreeMap::new();
    for (n, sealed) in sealed {
        let plain = opener.slice(*n, sealed).map_err(Some)?;
        let size = total.saturating_sub(n.saturating_mul(SLICE)).min(SLICE);
        let list = decode_slice(&plain).ok_or(None)?;
        if list.len() != usize::try_from(size).map_err(|_| None)? {
            return Err(None);
        }
        slices.insert(*n, list);
    }
    wanted
        .iter()
        .map(|&r| {
            let list = slices.get(&(r / SLICE)).ok_or(None)?;
            let at = usize::try_from(r % SLICE).map_err(|_| None)?;
            list.get(at)
                .map(|recipient| (r, recipient.clone()))
                .ok_or(None)
        })
        .collect()
}

fn check<'a>(envelope: &[u8], section: &'a [u8]) -> Option<(Envelope, Vec<dkim::Field<'a>>)> {
    let envelope = Envelope::decode(envelope)?;
    let fields = dkim::parse(section).ok()?;
    let count = envelope.signatures.len();
    if count == 0 || fields.len() <= count || !fields[0].is("received") {
        return None;
    }
    let mut hash: Option<Vec<u8>> = None;
    for (field, (_, alg)) in fields[1..=count].iter().zip(&envelope.signatures) {
        let bh: Vec<u8> = dkim::pending(field, *alg)
            .ok()?
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if *hash.get_or_insert_with(|| bh.clone()) != bh {
            return None;
        }
    }
    Some((envelope, fields))
}
