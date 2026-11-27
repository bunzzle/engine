use crypto::Token;
use sched::{Inbound, ReportBlock, ReportKind};
use smtp::report::Report;
use spool::MessageId;

pub(crate) fn inbound(
    token: &Token,
    id: MessageId,
    generation: u32,
    report: Report,
) -> Option<Inbound> {
    let (kind, blocks) = match report {
        Report::Bounces(list) if !list.is_empty() => (
            ReportKind::Bounce,
            list.into_iter()
                .map(|item| ReportBlock {
                    address: item.recipient,
                    status: item.status,
                    diagnostic: item.diagnostic,
                })
                .collect(),
        ),
        Report::Complaint { recipient } => (
            ReportKind::Complaint,
            vec![ReportBlock {
                address: recipient,
                status: (0, 0, 0),
                diagnostic: String::new(),
            }],
        ),
        Report::Bounces(_) | Report::Unknown => return None,
    };
    Some(Inbound {
        tenant: token.tenant,
        generation,
        message: id,
        recipient: token.recipient,
        kind,
        blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtp::report::Bounce;

    fn map(report: Report) -> Option<Inbound> {
        let mut token = Token::parse(&[b'a'; crypto::TOKEN_TEXT]).expect("token fixture");
        token.tenant = 7;
        token.recipient = 11;
        inbound(&token, MessageId::from_bytes([42; 16]), 3, report)
    }

    #[test]
    fn bounces_keep_fields_and_order() {
        let report = Report::Bounces(vec![
            Bounce {
                status: (5, 1, 1),
                original: Some("original@example.com".into()),
                recipient: Some("first@example.com".into()),
                diagnostic: "user unknown".into(),
            },
            Bounce {
                status: (4, 2, 2),
                original: Some("second@example.com".into()),
                recipient: None,
                diagnostic: "mailbox full".into(),
            },
        ]);
        assert_eq!(
            map(report),
            Some(Inbound {
                tenant: 7,
                generation: 3,
                message: MessageId::from_bytes([42; 16]),
                recipient: 11,
                kind: ReportKind::Bounce,
                blocks: vec![
                    ReportBlock {
                        address: Some("first@example.com".into()),
                        status: (5, 1, 1),
                        diagnostic: "user unknown".into(),
                    },
                    ReportBlock {
                        address: None,
                        status: (4, 2, 2),
                        diagnostic: "mailbox full".into(),
                    },
                ],
            })
        );
    }

    #[test]
    fn complaint_has_one_block() {
        let report = Report::Complaint {
            recipient: Some("recipient@example.com".into()),
        };
        let inbound = map(report).expect("complaint");
        assert_eq!(inbound.kind, ReportKind::Complaint);
        assert_eq!(
            inbound.blocks,
            [ReportBlock {
                address: Some("recipient@example.com".into()),
                status: (0, 0, 0),
                diagnostic: String::new(),
            }]
        );
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(map(Report::Unknown), None);
    }

    #[test]
    fn empty_bounces_return_none() {
        assert_eq!(map(Report::Bounces(Vec::new())), None);
    }
}
