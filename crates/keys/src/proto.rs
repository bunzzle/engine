use crypto::{DkimAlg, Plain, Secret, WRAP, Wrap};

use crate::Error;

pub const MAX_FRAME: usize = 4096;
const HEAD: usize = 9;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Hello {
        node: u32,
    },
    Create {
        tenant: u32,
        generation: u32,
        retention: u16,
    },
    Open {
        tenant: u32,
        generation: u32,
    },
    Unwrap {
        tenant: u32,
        batch: u64,
        wrap: Wrap,
    },
    Retention {
        tenant: u32,
        generation: u32,
        days: u16,
    },
    Settled {
        day: u32,
    },
    Delete {
        tenant: u32,
        generation: u32,
    },
    DkimNew {
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
    },
    Load {
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        blob: Vec<u8>,
    },
    Sign {
        tenant: u32,
        generation: u32,
        key: u32,
        alg: DkimAlg,
        digest: [u8; 32],
    },
}

pub enum Answer {
    Done,
    Hello {
        day: u32,
        naming: Secret<16>,
        ids: Secret<16>,
    },
    Keys {
        day: u32,
        oldest: u32,
        version: u8,
        data: Secret<32>,
        hash: Secret<16>,
        today: [u8; 32],
        tomorrow: [u8; 32],
    },
    Key(Secret<32>),
    Dkim {
        public: Vec<u8>,
        blob: Vec<u8>,
    },
    Signature(Vec<u8>),
    Refused(Error),
}

const REFUSALS: [Error; 11] = [
    Error::Unknown,
    Error::Generation,
    Error::Pending,
    Error::Gone,
    Error::Retention,
    Error::Open,
    Error::Failed,
    Error::Busy,
    Error::Bad,
    Error::Unreadable,
    Error::Conflict,
];

fn refusal_code(error: Error) -> u8 {
    REFUSALS
        .iter()
        .position(|&known| known == error)
        .map_or(u8::MAX, |i| u8::try_from(i).expect("few refusals"))
}

fn refusal(code: u8) -> Error {
    REFUSALS
        .get(usize::from(code))
        .copied()
        .unwrap_or(Error::Failed)
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        if self.bytes.len() < n {
            return Err(Error::Bad);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn secret<const N: usize>(&mut self) -> Result<Secret<N>, Error> {
        Ok(Secret::from_slice(self.take(N)?)?)
    }

    fn alg(&mut self) -> Result<DkimAlg, Error> {
        DkimAlg::from_code(self.u8()?).ok_or(Error::Bad)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let len = usize::from(self.u16()?);
        Ok(self.take(len)?.to_vec())
    }

    fn end(&self) -> Result<(), Error> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(Error::Bad)
        }
    }
}

fn length(bytes: &[u8]) -> [u8; 2] {
    u16::try_from(bytes.len())
        .expect("small field")
        .to_le_bytes()
}

fn frame(out: &mut Plain, op: u8, id: u32, body: &[&[u8]]) {
    let len: usize = body.iter().map(|part| part.len()).sum::<usize>() + HEAD - 4;
    out.extend_from_slice(&u32::try_from(len).expect("small frame").to_le_bytes());
    out.push(op);
    out.extend_from_slice(&id.to_le_bytes());
    for part in body {
        out.extend_from_slice(part);
    }
}

impl Request {
    pub fn size(&self) -> usize {
        match self {
            Self::Load { blob, .. } => HEAD + 15 + blob.len(),
            _ => 128,
        }
    }

    pub fn encode(&self, id: u32, out: &mut Plain) {
        match self {
            Self::Hello { node } => frame(out, 1, id, &[&node.to_le_bytes()]),
            Self::Create {
                tenant,
                generation,
                retention,
            } => frame(
                out,
                2,
                id,
                &[
                    &tenant.to_le_bytes(),
                    &generation.to_le_bytes(),
                    &retention.to_le_bytes(),
                ],
            ),
            Self::Open { tenant, generation } => frame(
                out,
                3,
                id,
                &[&tenant.to_le_bytes(), &generation.to_le_bytes()],
            ),
            Self::Unwrap {
                tenant,
                batch,
                wrap,
            } => frame(
                out,
                4,
                id,
                &[&tenant.to_le_bytes(), &batch.to_le_bytes(), &wrap.encode()],
            ),
            Self::Retention {
                tenant,
                generation,
                days,
            } => frame(
                out,
                5,
                id,
                &[
                    &tenant.to_le_bytes(),
                    &generation.to_le_bytes(),
                    &days.to_le_bytes(),
                ],
            ),
            Self::Settled { day } => frame(out, 6, id, &[&day.to_le_bytes()]),
            Self::Delete { tenant, generation } => frame(
                out,
                7,
                id,
                &[&tenant.to_le_bytes(), &generation.to_le_bytes()],
            ),
            Self::DkimNew { .. } | Self::Load { .. } | Self::Sign { .. } => {
                self.encode_dkim(id, out);
            }
        }
    }

    fn encode_dkim(&self, id: u32, out: &mut Plain) {
        match self {
            Self::DkimNew {
                tenant,
                generation,
                key,
                alg,
            } => frame(
                out,
                8,
                id,
                &[
                    &tenant.to_le_bytes(),
                    &generation.to_le_bytes(),
                    &key.to_le_bytes(),
                    &[alg.code()],
                ],
            ),
            Self::Load {
                tenant,
                generation,
                key,
                alg,
                blob,
            } => frame(
                out,
                9,
                id,
                &[
                    &tenant.to_le_bytes(),
                    &generation.to_le_bytes(),
                    &key.to_le_bytes(),
                    &[alg.code()],
                    &length(blob),
                    blob,
                ],
            ),
            Self::Sign {
                tenant,
                generation,
                key,
                alg,
                digest,
            } => frame(
                out,
                10,
                id,
                &[
                    &tenant.to_le_bytes(),
                    &generation.to_le_bytes(),
                    &key.to_le_bytes(),
                    &[alg.code()],
                    digest,
                ],
            ),
            _ => {}
        }
    }

    pub fn decode(op: u8, body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes: body };
        let request = match op {
            1 => Self::Hello { node: r.u32()? },
            2 => Self::Create {
                tenant: r.u32()?,
                generation: r.u32()?,
                retention: r.u16()?,
            },
            3 => Self::Open {
                tenant: r.u32()?,
                generation: r.u32()?,
            },
            4 => Self::Unwrap {
                tenant: r.u32()?,
                batch: r.u64()?,
                wrap: Wrap::decode(r.take(WRAP)?).map_err(|_| Error::Bad)?,
            },
            5 => Self::Retention {
                tenant: r.u32()?,
                generation: r.u32()?,
                days: r.u16()?,
            },
            6 => Self::Settled { day: r.u32()? },
            7 => Self::Delete {
                tenant: r.u32()?,
                generation: r.u32()?,
            },
            8 => Self::DkimNew {
                tenant: r.u32()?,
                generation: r.u32()?,
                key: r.u32()?,
                alg: r.alg()?,
            },
            9 => Self::Load {
                tenant: r.u32()?,
                generation: r.u32()?,
                key: r.u32()?,
                alg: r.alg()?,
                blob: r.bytes()?,
            },
            10 => Self::Sign {
                tenant: r.u32()?,
                generation: r.u32()?,
                key: r.u32()?,
                alg: r.alg()?,
                digest: r.array()?,
            },
            _ => return Err(Error::Bad),
        };
        r.end()?;
        Ok(request)
    }
}

impl Answer {
    pub fn encode(&self, id: u32, out: &mut Plain) {
        match self {
            Self::Done => frame(out, 0x80, id, &[]),
            Self::Hello { day, naming, ids } => {
                frame(
                    out,
                    0x81,
                    id,
                    &[&day.to_le_bytes(), naming.expose(), ids.expose()],
                );
            }
            Self::Keys {
                day,
                oldest,
                version,
                data,
                hash,
                today,
                tomorrow,
            } => frame(
                out,
                0x82,
                id,
                &[
                    &day.to_le_bytes(),
                    &oldest.to_le_bytes(),
                    &[*version],
                    data.expose(),
                    hash.expose(),
                    today,
                    tomorrow,
                ],
            ),
            Self::Key(key) => frame(out, 0x83, id, &[key.expose()]),
            Self::Dkim { public, blob } => {
                frame(
                    out,
                    0x84,
                    id,
                    &[&length(public), public, &length(blob), blob],
                );
            }
            Self::Signature(signature) => {
                frame(out, 0x85, id, &[&length(signature), signature]);
            }
            Self::Refused(error) => frame(out, 0xff, id, &[&[refusal_code(*error)]]),
        }
    }

    pub fn decode(op: u8, body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader { bytes: body };
        let answer = match op {
            0x80 => Self::Done,
            0x81 => Self::Hello {
                day: r.u32()?,
                naming: r.secret()?,
                ids: r.secret()?,
            },
            0x82 => Self::Keys {
                day: r.u32()?,
                oldest: r.u32()?,
                version: r.u8()?,
                data: r.secret()?,
                hash: r.secret()?,
                today: r.array()?,
                tomorrow: r.array()?,
            },
            0x83 => Self::Key(r.secret()?),
            0x84 => Self::Dkim {
                public: r.bytes()?,
                blob: r.bytes()?,
            },
            0x85 => Self::Signature(r.bytes()?),
            0xff => Self::Refused(refusal(r.u8()?)),
            _ => return Err(Error::Bad),
        };
        r.end()?;
        Ok(answer)
    }

    pub fn size(&self) -> usize {
        HEAD + match self {
            Self::Done => 0,
            Self::Hello { .. } => 36,
            Self::Keys { .. } => 121,
            Self::Key(_) => 32,
            Self::Dkim { public, blob } => 4 + public.len() + blob.len(),
            Self::Signature(signature) => 2 + signature.len(),
            Self::Refused(_) => 1,
        }
    }
}

#[derive(Default)]
pub struct Frames {
    buffer: Vec<u8>,
}

impl Frames {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    pub fn pop(&mut self) -> Result<Option<(u8, u32, Vec<u8>)>, Error> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes(self.buffer[..4].try_into().expect("4 bytes")) as usize;
        if !(HEAD - 4..=MAX_FRAME).contains(&len) {
            return Err(Error::Bad);
        }
        if self.buffer.len() < 4 + len {
            return Ok(None);
        }
        let op = self.buffer[4];
        let id = u32::from_le_bytes(self.buffer[5..9].try_into().expect("4 bytes"));
        let body = self.buffer[HEAD..4 + len].to_vec();
        let before = self.buffer.len();
        self.buffer.drain(..4 + len);
        let after = self.buffer.len();
        self.buffer.resize(before, 0);
        self.buffer.truncate(after);
        Ok(Some((op, id, body)))
    }

    pub fn wipe(&mut self) {
        let capacity = self.buffer.capacity();
        self.buffer.resize(capacity, 0);
        sys::mem::wipe(&mut self.buffer);
        self.buffer.clear();
    }
}

impl Drop for Frames {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use crypto::{DkimAlg, Plain, Secret, Wrap};

    use super::{Answer, Frames, Request};
    use crate::Error;

    fn requests() -> Vec<Request> {
        vec![
            Request::Hello { node: 1 },
            Request::Create {
                tenant: 2,
                generation: 3,
                retention: 30,
            },
            Request::Open {
                tenant: 2,
                generation: 3,
            },
            Request::Unwrap {
                tenant: 2,
                batch: 9,
                wrap: Wrap {
                    day: 100,
                    shard: 4,
                    generation: 3,
                    enc: [5; 32],
                    sealed: [6; 48],
                },
            },
            Request::Retention {
                tenant: 2,
                generation: 3,
                days: 7,
            },
            Request::Settled { day: 99 },
            Request::Delete {
                tenant: 2,
                generation: 3,
            },
            Request::DkimNew {
                tenant: 2,
                generation: 3,
                key: 4,
                alg: DkimAlg::RsaSha256,
            },
            Request::Load {
                tenant: 2,
                generation: 3,
                key: 4,
                alg: DkimAlg::Ed25519Sha256,
                blob: vec![9; 1_300],
            },
            Request::Sign {
                tenant: 2,
                generation: 3,
                key: 4,
                alg: DkimAlg::Ed25519Sha256,
                digest: [8; 32],
            },
        ]
    }

    #[test]
    fn requests_round_trip_in_one_stream() {
        let size = requests().iter().map(Request::size).sum();
        let mut out = Plain::with_capacity(size);
        for (id, request) in requests().iter().enumerate() {
            request.encode(u32::try_from(id).expect("small"), &mut out);
        }
        let mut frames = Frames::default();
        for byte in out.iter() {
            frames.push(&[*byte]);
        }
        let mut back = Vec::new();
        while let Some((op, id, body)) = frames.pop().expect("frame") {
            back.push((id, Request::decode(op, &body).expect("decodes")));
        }
        let expected: Vec<_> = requests()
            .into_iter()
            .enumerate()
            .map(|(i, r)| (u32::try_from(i).expect("small"), r))
            .collect();
        assert_eq!(back, expected);
    }

    #[test]
    fn answers_round_trip_with_their_sizes() {
        let answers = [
            Answer::Done,
            Answer::Hello {
                day: 1,
                naming: Secret::new([2; 16]),
                ids: Secret::new([9; 16]),
            },
            Answer::Keys {
                day: 1,
                oldest: 8,
                version: 1,
                data: Secret::new([3; 32]),
                hash: Secret::new([4; 16]),
                today: [5; 32],
                tomorrow: [6; 32],
            },
            Answer::Key(Secret::new([7; 32])),
            Answer::Dkim {
                public: vec![1; 294],
                blob: vec![2; 1_250],
            },
            Answer::Signature(vec![3; 256]),
            Answer::Refused(Error::Busy),
            Answer::Refused(Error::Conflict),
        ];
        for answer in answers {
            let mut out = Plain::with_capacity(answer.size());
            answer.encode(7, &mut out);
            assert_eq!(out.len(), answer.size());
            let mut frames = Frames::default();
            frames.push(&out);
            let (op, id, body) = frames.pop().expect("frame").expect("whole");
            assert_eq!(id, 7);
            let back = Answer::decode(op, &body).expect("decodes");
            let mut again = Plain::with_capacity(answer.size());
            back.encode(7, &mut again);
            assert_eq!(&again[..], &out[..]);
        }
    }

    #[test]
    fn malformed_frames_are_refused() {
        let mut frames = Frames::default();
        frames.push(&100_000u32.to_le_bytes());
        assert_eq!(frames.pop().err(), Some(Error::Bad));
        let mut out = Plain::with_capacity(64);
        Request::Settled { day: 1 }.encode(1, &mut out);
        let mut frames = Frames::default();
        frames.push(&out);
        let (op, _, mut body) = frames.pop().expect("frame").expect("whole");
        body.push(0);
        assert_eq!(Request::decode(op, &body), Err(Error::Bad));
        assert_eq!(Request::decode(99, &[]), Err(Error::Bad));
        assert_eq!(Request::decode(op, &body[..2]), Err(Error::Bad));
    }
}
