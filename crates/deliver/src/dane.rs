use dns::{Found, Name, Record, Type};
use tls::Tlsa;

use crate::mx::Dns;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Dane {
    None,
    Encrypt,
    Verify {
        names: Vec<String>,
        records: Vec<Tlsa>,
    },
    Failed {
        bogus: bool,
    },
}

pub(crate) async fn lookup<D: Dns>(dns: &D, port: u16, host: &Name, target: &Name) -> Dane {
    let mut bases = vec![target];
    if target != host {
        bases.push(host);
    }
    for base in bases {
        let Ok(name) = base
            .prefixed("_tcp")
            .and_then(|name| name.prefixed(&format!("_{port}")))
        else {
            continue;
        };
        let lookup = match dns.lookup(&name, Type::Tlsa).await {
            Ok(lookup) => lookup,
            Err(error) => {
                return Dane::Failed {
                    bogus: error == dns::Error::ServFail,
                };
            }
        };
        if !lookup.secure {
            continue;
        }
        let Found::Records(records) = &lookup.found else {
            continue;
        };
        let records: Vec<Tlsa> = records
            .iter()
            .filter_map(|record| match record {
                Record::Tlsa {
                    usage,
                    selector,
                    matching,
                    data,
                } => Some(Tlsa {
                    usage: *usage,
                    selector: *selector,
                    matching: *matching,
                    data: data.clone(),
                }),
                _ => None,
            })
            .collect();
        if records.is_empty() {
            continue;
        }
        let records: Vec<Tlsa> = records.into_iter().filter(Tlsa::usable).collect();
        if records.is_empty() {
            return Dane::Encrypt;
        }
        let mut names = vec![base.to_string()];
        if base != host {
            names.push(host.to_string());
        }
        return Dane::Verify { names, records };
    }
    Dane::None
}
