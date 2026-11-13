use config::parse;

const ALPHABET: &[char] = &[
    '[', ']', '=', '"', '\\', '#', '.', ',', '_', '-', ' ', '\t', '\n', '\r', '0', '1', '9', 'a',
    'n', 't', 'r', 'u', 'e', 'f', '\'', '{', '}', '+', 'x', '\u{0}', '\u{7f}', 'é', '\u{feff}',
];

const SEED_TEXT: &str = "[node]\nid = 3\nname = \"a\\tb\"\n[[listen]]\nports = [1, 2,]\n";

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("fits")).expect("fits")
    }
}

#[test]
fn random_input_never_panics() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        let len = rng.below(48);
        let text: String = (0..len)
            .map(|_| ALPHABET[rng.below(ALPHABET.len())])
            .collect();
        if let Err(error) = parse(&text) {
            assert!(error.line >= 1 && error.column >= 1, "{text:?}");
        }
    }
}

#[test]
fn mutated_files_never_panic() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let base: Vec<char> = SEED_TEXT.chars().collect();
    for _ in 0..20_000 {
        let mut text = base.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(text.len());
            match rng.below(3) {
                0 => text[at] = ALPHABET[rng.below(ALPHABET.len())],
                1 => {
                    text.remove(at);
                }
                _ => text.insert(at, ALPHABET[rng.below(ALPHABET.len())]),
            }
        }
        let text: String = text.into_iter().collect();
        if let Ok(mut root) = parse(&text) {
            let _ = root.table("node");
            let _ = root.tables("listen");
        }
    }
}
