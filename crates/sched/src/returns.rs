use control::{Table, domain_ok};
use crypto::{ANY, TOKEN_TEXT, TenantKeys, Token};

use crate::Envelope;

pub(crate) const RETURN_PREFIX: &str = "bounce";

pub(crate) fn return_sender(
    table: &Table,
    keys: &TenantKeys,
    prefix: &str,
    envelope: &Envelope,
    tenant: u32,
    id: [u8; 16],
    recipient: Option<u32>,
) -> Option<String> {
    if envelope.smtp || keys.tenant() != tenant {
        return None;
    }
    let (_, sender_domain) = envelope.sender.rsplit_once('@')?;
    let record = table.return_path(tenant, sender_domain)?;
    if prefix.len() + record.name.len() + TOKEN_TEXT + 3 > 256 || prefix.contains('.') {
        return None;
    }
    let domain = format!("{prefix}.{}", record.name);
    if !domain_ok(&domain) {
        return None;
    }
    let token = Token::sign(keys, recipient.unwrap_or(ANY), id).text();
    Some(format!("b{token}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use control::{Domain, Limits, Object, Snapshot, State, Tenant, Verification};
    use crypto::Secret;

    const TENANT: u32 = 7;
    const ID: [u8; 16] = *b"public-message-1";

    fn keys(tenant: u32) -> TenantKeys {
        TenantKeys::new(
            tenant,
            1,
            &Secret::new([1; 32]),
            1,
            Secret::new([2; 16]),
            Secret::new([3; 16]),
        )
    }

    fn domain(id: u32, name: &str, return_path: bool) -> Object {
        Object::Domain(Domain {
            id,
            tenant: TENANT,
            generation: 1,
            state: Verification::Verified,
            return_path,
            rsa: 0,
            ed25519: 0,
            name: name.into(),
        })
    }

    fn table(mut objects: Vec<Object>) -> Table {
        objects.push(Object::Tenant(Tenant {
            id: TENANT,
            generation: 1,
            state: State::Active,
            default_pool: 1,
            pools: vec![1],
            limits: Limits::default(),
        }));
        let mut table = Table::default();
        table.load(Snapshot {
            version: 1,
            objects,
        });
        table
    }

    fn enabled_table() -> Table {
        table(vec![domain(1, "a.com", true)])
    }

    fn envelope(sender: &str) -> Envelope {
        Envelope {
            sender: sender.into(),
            ..Envelope::default()
        }
    }

    fn rewrite(table: &Table, prefix: &str, sender: &str) -> Option<String> {
        return_sender(
            table,
            &keys(TENANT),
            prefix,
            &envelope(sender),
            TENANT,
            ID,
            None,
        )
    }

    #[test]
    fn single_recipient_has_a_verified_token() {
        let keys = keys(TENANT);
        let sender = return_sender(
            &enabled_table(),
            &keys,
            "bounce",
            &envelope("x@a.com"),
            TENANT,
            ID,
            Some(42),
        )
        .expect("return sender");
        let (local, domain) = sender.split_once('@').expect("address");
        assert_eq!(domain, "bounce.a.com");
        assert_eq!(local.len(), 56);
        let text = local.strip_prefix('b').expect("token prefix");
        assert!(text.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')));
        let token = Token::parse(text.as_bytes()).expect("token");
        assert_eq!(token.tenant, TENANT);
        assert_eq!(token.recipient, 42);
        assert_eq!(token.id, ID);
        assert!(token.verify(&keys));
    }

    #[test]
    fn several_recipients_use_any() {
        let sender = rewrite(&enabled_table(), "bounce", "x@a.com").expect("return sender");
        let (local, _) = sender.split_once('@').expect("address");
        let text = local.strip_prefix('b').expect("token prefix");
        let token = Token::parse(text.as_bytes()).expect("token");
        assert_eq!(token.recipient, ANY);
        assert!(token.verify(&keys(TENANT)));
    }

    #[test]
    fn smtp_sender_is_kept() {
        let envelope = Envelope {
            smtp: true,
            ..envelope("x@a.com")
        };
        assert_eq!(
            return_sender(
                &enabled_table(),
                &keys(TENANT),
                "bounce",
                &envelope,
                TENANT,
                ID,
                None
            ),
            None
        );
    }

    #[test]
    fn null_sender_is_kept() {
        assert_eq!(rewrite(&enabled_table(), "bounce", ""), None);
    }

    #[test]
    fn sender_without_a_matching_domain_is_kept() {
        let table = enabled_table();
        assert_eq!(rewrite(&table, "bounce", "x"), None);
        assert_eq!(rewrite(&table, "bounce", "x@b.com"), None);
    }

    #[test]
    fn keys_from_another_tenant_are_rejected() {
        assert_eq!(
            return_sender(
                &enabled_table(),
                &keys(TENANT + 1),
                "bounce",
                &envelope("x@a.com"),
                TENANT,
                ID,
                None,
            ),
            None
        );
    }

    #[test]
    fn domain_without_the_flag_keeps_the_sender() {
        let table = table(vec![domain(1, "a.com", false)]);
        assert_eq!(rewrite(&table, "bounce", "x@a.com"), None);
    }

    #[test]
    fn longest_match_without_the_flag_keeps_the_sender() {
        let table = table(vec![
            domain(1, "a.com", true),
            domain(2, "news.a.com", false),
        ]);
        assert_eq!(rewrite(&table, "bounce", "x@news.a.com"), None);
    }

    #[test]
    fn subdomain_sender_uses_the_record_name() {
        let sender =
            rewrite(&enabled_table(), "bounce", "\"x@y\"@news.a.com").expect("return sender");
        assert_eq!(
            sender.split_once('@').map(|(_, domain)| domain),
            Some("bounce.a.com")
        );
    }

    #[test]
    fn return_sender_is_limited_to_256_octets() {
        let name = format!(
            "{}.{}.{}.ddddd",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63)
        );
        let table = table(vec![domain(1, &name, true)]);
        let sender = format!("x@{name}");
        assert_eq!(
            rewrite(&table, "b", &sender).expect("return sender").len(),
            256
        );
        assert_eq!(rewrite(&table, "bb", &sender), None);
    }

    #[test]
    fn prefix_must_be_one_valid_label() {
        let table = enabled_table();
        assert_eq!(rewrite(&table, "a.b", "x@a.com"), None);
        assert_eq!(rewrite(&table, "", "x@a.com"), None);
        assert_eq!(rewrite(&table, "-bounce", "x@a.com"), None);
    }
}
