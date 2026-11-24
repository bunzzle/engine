use std::fmt::Write;

use crate::board::{AGE, Board, Def, Kind, Slab, UP};

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
        let live: Vec<(String, &Slab)> = self
            .slabs
            .iter()
            .enumerate()
            .filter(|(core, _)| stamps[*core].is_some())
            .map(|(core, slab)| (format!("core=\"{core}\""), slab))
            .collect();
        self.families(format, self.defs, &live, out);
        if let Some(node) = self.node.as_deref().filter(|n| n.published().is_some()) {
            self.families(format, node.defs(), &[(String::new(), node)], out);
        }
        if let Some(tenants) = self.tenants.as_ref().filter(|t| !t.ids.is_empty()) {
            let width = tenants.ids.len();
            let rows: Vec<(String, &Slab)> = (0..self.slabs.len())
                .filter(|core| stamps[*core].is_some())
                .flat_map(|core| {
                    tenants.ids.iter().enumerate().map(move |(index, id)| {
                        (
                            format!("core=\"{core}\",tenant=\"{id}\""),
                            &tenants.slabs[core * width + index],
                        )
                    })
                })
                .collect();
            self.families(format, tenants.defs, &rows, out);
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

    fn families(&self, format: Format, defs: &[Def], slabs: &[(String, &Slab)], out: &mut String) {
        let prefix = self.prefix;
        for (index, def) in defs.iter().enumerate() {
            let name = def.name;
            match def.kind {
                Kind::Counter | Kind::Gauge => {
                    let counter = def.kind == Kind::Counter;
                    let family = if counter && format == Format::Text {
                        "_total"
                    } else {
                        ""
                    };
                    let sample = if counter { "_total" } else { "" };
                    let kind = if counter { "counter" } else { "gauge" };
                    self.header(out, name, family, def.help, kind);
                    for (labels, slab) in slabs {
                        let value = slab.get(index).unwrap_or(0);
                        let _ = writeln!(out, "{prefix}_{name}{sample}{} {value}", braces(labels));
                    }
                }
                Kind::Histogram(bounds) => {
                    self.header(out, name, "", def.help, "histogram");
                    for (labels, slab) in slabs {
                        let Some(histogram) = slab.histogram(index) else {
                            continue;
                        };
                        let join = if labels.is_empty() { "" } else { "," };
                        let mut count = 0u64;
                        for (bucket, value) in histogram.buckets.iter().enumerate() {
                            count = count.saturating_add(*value);
                            let le = bounds
                                .get(bucket)
                                .map_or_else(|| "+Inf".to_owned(), |b| seconds(*b));
                            let _ = writeln!(
                                out,
                                "{prefix}_{name}_bucket{{{labels}{join}le=\"{le}\"}} {count}"
                            );
                        }
                        let braced = braces(labels);
                        let _ = writeln!(
                            out,
                            "{prefix}_{name}_sum{braced} {}",
                            seconds(histogram.sum)
                        );
                        let _ = writeln!(out, "{prefix}_{name}_count{braced} {count}");
                    }
                }
            }
        }
    }

    fn header(&self, out: &mut String, name: &str, suffix: &str, help: &str, kind: &str) {
        let prefix = self.prefix;
        let _ = writeln!(out, "# HELP {prefix}_{name}{suffix} {help}");
        let _ = writeln!(out, "# TYPE {prefix}_{name}{suffix} {kind}");
    }
}

fn braces(labels: &str) -> String {
    if labels.is_empty() {
        String::new()
    } else {
        format!("{{{labels}}}")
    }
}

fn seconds(micros: u64) -> String {
    let fraction = format!("{:06}", micros % 1_000_000);
    let fraction = fraction.trim_end_matches('0');
    let fraction = if fraction.is_empty() { "0" } else { fraction };
    format!("{}.{fraction}", micros / 1_000_000)
}
