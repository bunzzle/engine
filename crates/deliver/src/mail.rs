use std::fmt::Write;

use crate::gzip::gzip;
use crate::report::Report;

pub(crate) const MAX_JSON: usize = 1 << 20;
const BOUNDARY: &str = "=_tlsrpt";
const LINE: usize = 76;

pub(crate) fn report_mail(report: &Report, from: &str, to: &[String]) -> Option<Vec<u8>> {
    let json = report.json();
    if json.len() > MAX_JSON || to.is_empty() {
        return None;
    }
    let packed = dkim::base64::encode(&gzip(json.as_bytes()));
    let name = format!(
        "{}!{}!{}!{}.json.gz",
        report.submitter,
        report.domain,
        report.start(),
        report.end()
    );
    let mut out = String::new();
    let mut header = |name: &str, value: &str| {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    };
    header("From", from);
    header("To", &to.join(", "));
    header(
        "Subject",
        &format!(
            "Report Domain: {} Submitter: {} Report-ID: <{}>",
            report.domain,
            report.submitter,
            report.id()
        ),
    );
    header("TLS-Report-Domain", &report.domain);
    header("TLS-Report-Submitter", &report.submitter);
    header("MIME-Version", "1.0");
    header(
        "Content-Type",
        &format!("multipart/report; report-type=\"tlsrpt\"; boundary=\"{BOUNDARY}\""),
    );
    let _ = write!(
        out,
        "\r\n--{BOUNDARY}\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n\
         TLS report for {} from {}.\r\n\r\n--{BOUNDARY}\r\n\
         Content-Type: application/tlsrpt+gzip\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=\"{name}\"\r\n\r\n",
        report.domain, report.submitter
    );
    for line in packed.as_bytes().chunks(LINE) {
        out.push_str(std::str::from_utf8(line).ok()?);
        out.push_str("\r\n");
    }
    let _ = write!(out, "--{BOUNDARY}--\r\n");
    Some(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::{MAX_JSON, report_mail};
    use crate::report::{Applied, Applies, Report};

    fn report(organization: String) -> Report {
        Report {
            organization,
            contact: "ops@sender.example".into(),
            submitter: "sender.example".into(),
            domain: "example.com".into(),
            day: 20_000,
            policies: vec![Applies {
                policy: Applied::None,
                success: 1,
                failure: 0,
                details: Vec::new(),
            }],
        }
    }

    #[test]
    fn builds_a_multipart_report() {
        let to = ["a@example.com".to_owned(), "b@example.com".to_owned()];
        let mail = report_mail(&report("Ops".into()), "tlsrpt@sender.example", &to).expect("mail");
        let text = String::from_utf8(mail).expect("ascii");
        let (head, body) = text.split_once("\r\n\r\n").expect("header");
        assert!(head.contains("From: tlsrpt@sender.example\r\n"));
        assert!(head.contains("To: a@example.com, b@example.com\r\n"));
        assert!(head.contains("TLS-Report-Domain: example.com\r\n"));
        assert!(head.contains("TLS-Report-Submitter: sender.example\r\n"));
        assert!(head.contains("Report-ID: <2024-10-04.example.com@sender.example>"));
        assert!(head.contains("multipart/report; report-type=\"tlsrpt\""));
        assert!(body.contains("Content-Type: application/tlsrpt+gzip\r\n"));
        assert!(
            body.contains("filename=\"sender.example!example.com!1728000000!1728086399.json.gz\"")
        );
        let encoded: String = body
            .split("\r\n\r\n")
            .nth(3)
            .expect("attachment")
            .lines()
            .take_while(|line| !line.starts_with("--"))
            .inspect(|line| assert!(line.len() <= 76))
            .collect();
        let packed = dkim::base64::decode(encoded.as_bytes()).expect("base64");
        assert_eq!(&packed[..3], [0x1f, 0x8b, 8]);
        assert!(text.lines().all(|line| line.len() <= 998));
        assert!(encoded.len() > 76);
        assert!(body.ends_with("--=_tlsrpt--\r\n"));
    }

    #[test]
    fn refuses_huge_reports_and_no_recipients() {
        let to = ["a@example.com".to_owned()];
        assert_eq!(
            report_mail(&report("x".repeat(MAX_JSON)), "f@s.example", &to),
            None
        );
        assert_eq!(report_mail(&report("x".into()), "f@s.example", &[]), None);
    }
}
