use std::fmt::Write;
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResultType {
    StarttlsNotSupported,
    CertificateHostMismatch,
    CertificateExpired,
    CertificateNotTrusted,
    ValidationFailure,
    TlsaInvalid,
    DnssecInvalid,
    DaneRequired,
    StsPolicyFetchError,
    StsPolicyInvalid,
    StsWebpkiInvalid,
}

impl ResultType {
    pub fn name(self) -> &'static str {
        match self {
            Self::StarttlsNotSupported => "starttls-not-supported",
            Self::CertificateHostMismatch => "certificate-host-mismatch",
            Self::CertificateExpired => "certificate-expired",
            Self::CertificateNotTrusted => "certificate-not-trusted",
            Self::ValidationFailure => "validation-failure",
            Self::TlsaInvalid => "tlsa-invalid",
            Self::DnssecInvalid => "dnssec-invalid",
            Self::DaneRequired => "dane-required",
            Self::StsPolicyFetchError => "sts-policy-fetch-error",
            Self::StsPolicyInvalid => "sts-policy-invalid",
            Self::StsWebpkiInvalid => "sts-webpki-invalid",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Applied {
    Sts { lines: Vec<String>, mx: Vec<String> },
    Tlsa { records: Vec<String> },
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detail {
    pub result: ResultType,
    pub sending: IpAddr,
    pub mx: Option<String>,
    pub receiving: Option<IpAddr>,
    pub count: u64,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applies {
    pub policy: Applied,
    pub success: u64,
    pub failure: u64,
    pub details: Vec<Detail>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub organization: String,
    pub contact: String,
    pub submitter: String,
    pub domain: String,
    pub day: u64,
    pub policies: Vec<Applies>,
}

const DAY_SECONDS: u64 = 86_400;

impl Report {
    pub fn id(&self) -> String {
        format!("{}.{}@{}", date(self.day), self.domain, self.submitter)
    }

    pub fn start(&self) -> u64 {
        self.day * DAY_SECONDS
    }

    pub fn end(&self) -> u64 {
        self.start() + DAY_SECONDS - 1
    }

    pub fn json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"organization-name\":");
        string(&self.organization, &mut out);
        out.push_str(",\"date-range\":{\"start-datetime\":");
        string(&datetime(self.start()), &mut out);
        out.push_str(",\"end-datetime\":");
        string(&datetime(self.end()), &mut out);
        out.push_str("},\"contact-info\":");
        string(&self.contact, &mut out);
        out.push_str(",\"report-id\":");
        string(&self.id(), &mut out);
        out.push_str(",\"policies\":[");
        for (i, applies) in self.policies.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            self.applies(applies, &mut out);
        }
        out.push_str("]}");
        out
    }

    fn applies(&self, applies: &Applies, out: &mut String) {
        out.push_str("{\"policy\":{\"policy-type\":");
        match &applies.policy {
            Applied::Sts { lines, mx } => {
                string("sts", out);
                out.push_str(",\"policy-string\":");
                strings(lines, out);
                out.push_str(",\"policy-domain\":");
                string(&self.domain, out);
                out.push_str(",\"mx-host\":");
                strings(mx, out);
            }
            Applied::Tlsa { records } => {
                string("tlsa", out);
                out.push_str(",\"policy-string\":");
                strings(records, out);
                out.push_str(",\"policy-domain\":");
                string(&self.domain, out);
            }
            Applied::None => {
                string("no-policy-found", out);
                out.push_str(",\"policy-domain\":");
                string(&self.domain, out);
            }
        }
        let _ = write!(
            out,
            "}},\"summary\":{{\"total-successful-session-count\":{},\"total-failure-session-count\":{}}}",
            applies.success, applies.failure
        );
        if !applies.details.is_empty() {
            out.push_str(",\"failure-details\":[");
            for (i, detail) in applies.details.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                self::detail(detail, out);
            }
            out.push(']');
        }
        out.push('}');
    }
}

fn detail(detail: &Detail, out: &mut String) {
    out.push_str("{\"result-type\":");
    string(detail.result.name(), out);
    out.push_str(",\"sending-mta-ip\":");
    string(&detail.sending.to_string(), out);
    if let Some(mx) = &detail.mx {
        out.push_str(",\"receiving-mx-hostname\":");
        string(mx, out);
    }
    if let Some(ip) = detail.receiving {
        out.push_str(",\"receiving-ip\":");
        string(&ip.to_string(), out);
    }
    let _ = write!(out, ",\"failed-session-count\":{}", detail.count);
    if let Some(reason) = &detail.reason {
        out.push_str(",\"failure-reason-code\":");
        string(reason, out);
    }
    out.push('}');
}

fn strings(items: &[String], out: &mut String) {
    out.push('[');
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        string(item, out);
    }
    out.push(']');
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn date(days: u64) -> String {
    let (year, month, day) = civil(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn datetime(seconds: u64) -> String {
    let time = seconds % DAY_SECONDS;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date(seconds / DAY_SECONDS),
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{Applied, Applies, Detail, Report, ResultType, datetime};

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    #[test]
    fn writes_the_rfc_example_shape() {
        let lines = [
            "version: STSv1",
            "mode: testing",
            "mx: *.mail.company-y.example",
            "max_age: 86400",
        ];
        let report = Report {
            organization: "Company-X".into(),
            contact: "sts-reporting@company-x.example".into(),
            submitter: "company-x.example".into(),
            domain: "company-y.example".into(),
            day: 16_892,
            policies: vec![Applies {
                policy: Applied::Sts {
                    lines: lines.iter().map(ToString::to_string).collect(),
                    mx: vec!["*.mail.company-y.example".into()],
                },
                success: 5326,
                failure: 303,
                details: vec![
                    Detail {
                        result: ResultType::CertificateExpired,
                        sending: ip("2001:db8:abcd:0012::1"),
                        mx: Some("mx1.mail.company-y.example".into()),
                        receiving: None,
                        count: 100,
                        reason: None,
                    },
                    Detail {
                        result: ResultType::ValidationFailure,
                        sending: ip("198.51.100.62"),
                        mx: Some("mx-backup.mail.company-y.example".into()),
                        receiving: Some(ip("203.0.113.58")),
                        count: 3,
                        reason: Some("X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED".into()),
                    },
                ],
            }],
        };
        let expected = concat!(
            r#"{"organization-name":"Company-X","#,
            r#""date-range":{"start-datetime":"2016-04-01T00:00:00Z","end-datetime":"2016-04-01T23:59:59Z"},"#,
            r#""contact-info":"sts-reporting@company-x.example","#,
            r#""report-id":"2016-04-01.company-y.example@company-x.example","#,
            r#""policies":[{"policy":{"policy-type":"sts","#,
            r#""policy-string":["version: STSv1","mode: testing","mx: *.mail.company-y.example","max_age: 86400"],"#,
            r#""policy-domain":"company-y.example","mx-host":["*.mail.company-y.example"]},"#,
            r#""summary":{"total-successful-session-count":5326,"total-failure-session-count":303},"#,
            r#""failure-details":[{"result-type":"certificate-expired","sending-mta-ip":"2001:db8:abcd:12::1","#,
            r#""receiving-mx-hostname":"mx1.mail.company-y.example","failed-session-count":100},"#,
            r#"{"result-type":"validation-failure","sending-mta-ip":"198.51.100.62","#,
            r#""receiving-mx-hostname":"mx-backup.mail.company-y.example","receiving-ip":"203.0.113.58","#,
            r#""failed-session-count":3,"failure-reason-code":"X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"}]}]}"#,
        );
        assert_eq!(report.json(), expected);
        assert_eq!(
            (report.start(), report.end()),
            (1_459_468_800, 1_459_555_199)
        );
    }

    #[test]
    fn writes_tlsa_and_no_policy_and_escapes() {
        let report = Report {
            organization: "A \"B\"\n".into(),
            contact: "c@d.example".into(),
            submitter: "d.example".into(),
            domain: "mx.e.example".into(),
            day: 0,
            policies: vec![
                Applies {
                    policy: Applied::Tlsa {
                        records: vec!["3 1 1 abcd".into()],
                    },
                    success: 1,
                    failure: 0,
                    details: Vec::new(),
                },
                Applies {
                    policy: Applied::None,
                    success: 2,
                    failure: 1,
                    details: vec![Detail {
                        result: ResultType::StarttlsNotSupported,
                        sending: ip("10.0.0.1"),
                        mx: None,
                        receiving: Some(ip("10.0.0.2")),
                        count: 1,
                        reason: None,
                    }],
                },
            ],
        };
        let json = report.json();
        assert!(json.starts_with(r#"{"organization-name":"A \"B\"\n","#));
        assert!(json.contains(r#"{"policy":{"policy-type":"tlsa","policy-string":["3 1 1 abcd"],"policy-domain":"mx.e.example"},"summary":{"total-successful-session-count":1,"total-failure-session-count":0}}"#));
        assert!(json.contains(
            r#"{"policy":{"policy-type":"no-policy-found","policy-domain":"mx.e.example"},"#
        ));
        assert!(json.contains(r#"[{"result-type":"starttls-not-supported","sending-mta-ip":"10.0.0.1","receiving-ip":"10.0.0.2","failed-session-count":1}]"#));
        assert_eq!(datetime(0), "1970-01-01T00:00:00Z");
        assert_eq!(datetime(951_782_400 + 86_399), "2000-02-29T23:59:59Z");
    }
}
