use control::domain_ok;

pub const MAX_ADDRESS: usize = 254;

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const BIAS: u32 = 72;
const FIRST: u32 = 128;

pub fn normalize(address: &str) -> Option<String> {
    let lower = address.to_ascii_lowercase();
    let (local, domain) = lower.rsplit_once('@')?;
    if local.is_empty() {
        return None;
    }
    let mut labels = Vec::new();
    for label in domain.split('.') {
        if label.is_ascii() {
            labels.push(label.to_owned());
        } else {
            labels.push(format!("xn--{}", punycode(label)?));
        }
    }
    let domain = labels.join(".");
    let normal = format!("{local}@{domain}");
    (domain_ok(&domain) && normal.len() <= MAX_ADDRESS).then_some(normal)
}

pub fn punycode(label: &str) -> Option<String> {
    let points: Vec<u32> = label.chars().map(u32::from).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = u32::try_from(out.len()).ok()?;
    if basic > 0 {
        out.push('-');
    }
    let total = u32::try_from(points.len()).ok()?;
    let mut handled = basic;
    let mut point = FIRST;
    let mut delta: u32 = 0;
    let mut bias = BIAS;
    while handled < total {
        let least = points.iter().copied().filter(|&c| c >= point).min()?;
        delta = delta.checked_add((least - point).checked_mul(handled + 1)?)?;
        point = least;
        for &code in &points {
            if code < point {
                delta = delta.checked_add(1)?;
            }
            if code == point {
                let mut rest = delta;
                let mut step = BASE;
                loop {
                    let limit = threshold(step, bias);
                    if rest < limit {
                        break;
                    }
                    out.push(digit(limit + (rest - limit) % (BASE - limit)));
                    rest = (rest - limit) / (BASE - limit);
                    step += BASE;
                }
                out.push(digit(rest));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        point = point.checked_add(1)?;
    }
    Some(out)
}

fn threshold(step: u32, bias: u32) -> u32 {
    if step <= bias {
        TMIN
    } else if step >= bias + TMAX {
        TMAX
    } else {
        step - bias
    }
}

fn digit(d: u32) -> char {
    let d = u8::try_from(d).expect("digit below 36");
    char::from(if d < 26 { b'a' + d } else { b'0' + d - 26 })
}

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / DAMP } else { delta / 2 };
    delta += delta / points;
    let mut step = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        step += BASE;
    }
    step + (BASE - TMIN + 1) * delta / (delta + SKEW)
}
