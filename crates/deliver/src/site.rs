use dns::Name;

use crate::settings::Site;

const LONGEST: usize = 255;

pub fn name(domain: &str, hosts: &[Name], rules: &[Site]) -> String {
    let mut names: Vec<String> = hosts
        .iter()
        .map(|host| host.to_string().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    names.sort_unstable();
    names.dedup();
    for rule in rules {
        if !names.is_empty() && names.iter().all(|host| rule.matches(host)) {
            return rule.name.clone();
        }
    }
    let joined = names.join(",");
    if joined.len() > LONGEST {
        domain.trim_end_matches('.').to_ascii_lowercase()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use dns::Name;

    use super::{LONGEST, name};
    use crate::settings::Site;

    fn hosts(names: &[&str]) -> Vec<Name> {
        names
            .iter()
            .map(|name| Name::parse(name).expect("name"))
            .collect()
    }

    fn rule(name: &str, suffixes: &[&str]) -> Site {
        Site {
            name: name.to_owned(),
            suffixes: suffixes.iter().map(|s| s.to_ascii_lowercase()).collect(),
        }
    }

    #[test]
    fn hosts_are_sorted_and_deduplicated() {
        let hosts = hosts(&["b.example.net", "a.example.net", "b.example.net"]);
        assert_eq!(
            name("example.org", &hosts, &[]),
            "a.example.net,b.example.net"
        );
    }

    #[test]
    fn case_and_trailing_dots_are_normalised() {
        let hosts = hosts(&["Mx2.Example.NET.", "MX1.example.net"]);
        assert_eq!(
            name("example.org", &hosts, &[]),
            "mx1.example.net,mx2.example.net"
        );
    }

    #[test]
    fn implicit_mx_is_the_domain_itself() {
        let hosts = hosts(&["example.org"]);
        assert_eq!(name("example.org", &hosts, &[]), "example.org");
    }

    #[test]
    fn a_rule_applies_when_every_host_matches_it() {
        let hosts = hosts(&["mx1.google.com", "ASPMX.l.google.com"]);
        let rules = [
            rule("google", &["google.com"]),
            rule("other", &["l.google.com"]),
        ];
        assert_eq!(name("example.org", &hosts, &rules), "google");
    }

    #[test]
    fn a_rule_needs_every_host_to_match() {
        let hosts = hosts(&["mx1.google.com", "mx.example.net"]);
        let rules = [rule("google", &["google.com"])];
        assert_eq!(
            name("example.org", &hosts, &rules),
            "mx.example.net,mx1.google.com"
        );
    }

    #[test]
    fn suffixes_match_on_whole_labels() {
        let rules = [rule("google", &["google.com"])];
        let evil = hosts(&["evilgoogle.com"]);
        assert_eq!(name("example.org", &evil, &rules), "evilgoogle.com");
        let good = hosts(&["google.com", "x.google.com"]);
        assert_eq!(name("example.org", &good, &rules), "google");
    }

    #[test]
    fn a_long_set_falls_back_to_the_domain() {
        let label = "a".repeat(62);
        let names: Vec<String> = (0..4).map(|n| format!("{label}{n}.example.net")).collect();
        let hosts: Vec<Name> = names
            .iter()
            .map(|name| Name::parse(name).expect("name"))
            .collect();
        let joined = names.join(",");
        assert!(joined.len() > LONGEST);
        assert_eq!(name("example.org", &hosts, &[]), "example.org");
        assert_eq!(name("Example.ORG.", &hosts, &[]), "example.org");
        let short = &hosts[..3];
        let joined: String = short
            .iter()
            .map(|host| host.to_string().trim_end_matches('.').to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        assert!(joined.len() <= LONGEST);
        assert_eq!(name("example.org", short, &[]), joined);
    }
}
