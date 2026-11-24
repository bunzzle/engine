use std::fmt::Write;

use crate::board::{AGE, Board, Kind, Slab, UP};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    OpenMetrics,
}

impl Format {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain; version=0.0.4; charset=utf-8",
            Self::OpenMetrics => "application/openmetrics-text; version=1.0.0; charset=utf-8",
        }
    }
}

impl Board {
    pub fn render(&self, format: Format, now_ms: u64, stale_ms: u64, out: &mut String) {
        let stamps: Vec<Option<u64>> = self.slabs.iter().map(Slab::published).collect();
        for (index, def) in self.defs.iter().enumerate() {
            let counter = def.kind == Kind::Counter;
            let family = if counter && format == Format::Text {
                "_total"
            } else {
                ""
            };
            let sample = if counter { "_total" } else { "" };
            let kind = if counter { "counter" } else { "gauge" };
            self.header(out, def.name, family, def.help, kind);
            for (core, slab) in self.slabs.iter().enumerate() {
                if stamps[core].is_none() {
                    continue;
                }
                let value = slab.get(index).unwrap_or(0);
                let _ = writeln!(
                    out,
                    "{}_{}{sample}{{core=\"{core}\"}} {value}",
                    self.prefix, def.name
                );
            }
        }
        self.header(
            out,
            UP,
            "",
            "1 when the core published within the stale window",
            "gauge",
        );
        for (core, stamp) in stamps.iter().enumerate() {
            let up = stamp.is_some_and(|at| now_ms.saturating_sub(at) <= stale_ms);
            let _ = writeln!(
                out,
                "{}_{UP}{{core=\"{core}\"}} {}",
                self.prefix,
                u8::from(up)
            );
        }
        self.header(
            out,
            AGE,
            "",
            "Seconds since the core last published",
            "gauge",
        );
        for (core, stamp) in stamps.iter().enumerate() {
            if let Some(at) = stamp {
                let age = now_ms.saturating_sub(*at);
                let _ = writeln!(
                    out,
                    "{}_{AGE}{{core=\"{core}\"}} {}.{:03}",
                    self.prefix,
                    age / 1000,
                    age % 1000
                );
            }
        }
        if format == Format::OpenMetrics {
            out.push_str("# EOF\n");
        }
    }

    fn header(&self, out: &mut String, name: &str, suffix: &str, help: &str, kind: &str) {
        let prefix = self.prefix;
        let _ = writeln!(out, "# HELP {prefix}_{name}{suffix} {help}");
        let _ = writeln!(out, "# TYPE {prefix}_{name}{suffix} {kind}");
    }
}
