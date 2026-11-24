use std::sync::Arc;
use std::thread;

use metrics::{Board, Def, Invalid, Kind};

const fn def(name: &'static str, kind: Kind) -> Def {
    Def {
        name,
        help: "help",
        kind,
    }
}

static TWO: [Def; 2] = [def("sent", Kind::Counter), def("queued", Kind::Gauge)];

#[test]
fn refuses_bad_catalogs() {
    static TOTAL: [Def; 1] = [def("sent_total", Kind::Counter)];
    static DASH: [Def; 1] = [def("bad-name", Kind::Gauge)];
    static DIGIT: [Def; 1] = [def("1x", Kind::Gauge)];
    static EMPTY: [Def; 1] = [def("", Kind::Gauge)];
    static TWICE: [Def; 2] = [def("a", Kind::Gauge), def("a", Kind::Counter)];
    static SUFFIX: [Def; 2] = [def("a", Kind::Counter), def("a_total", Kind::Gauge)];
    static BUILTIN: [Def; 1] = [def("core_up", Kind::Gauge)];
    static NEWLINE: [Def; 1] = [Def {
        name: "x",
        help: "a\nb",
        kind: Kind::Gauge,
    }];
    static SLASH: [Def; 1] = [Def {
        name: "x",
        help: "a\\b",
        kind: Kind::Gauge,
    }];
    let check = |defs: &'static [Def]| Board::new("bunzzle", defs, 1).err();
    assert_eq!(check(&TOTAL), Some(Invalid::Name("sent_total")));
    assert_eq!(check(&DASH), Some(Invalid::Name("bad-name")));
    assert_eq!(check(&DIGIT), Some(Invalid::Name("1x")));
    assert_eq!(check(&EMPTY), Some(Invalid::Name("")));
    assert_eq!(check(&TWICE), Some(Invalid::Duplicate("a")));
    assert_eq!(check(&SUFFIX), Some(Invalid::Duplicate("a_total")));
    assert_eq!(check(&BUILTIN), Some(Invalid::Duplicate("core_up")));
    assert_eq!(check(&NEWLINE), Some(Invalid::Help("x")));
    assert_eq!(check(&SLASH), Some(Invalid::Help("x")));
    assert_eq!(Board::new("bunzzle", &TWO, 0).err(), Some(Invalid::Cores));
    assert_eq!(
        Board::new("bun.zzle", &TWO, 1).err(),
        Some(Invalid::Name("bun.zzle"))
    );
}

#[test]
fn slabs_hold_values_and_stamps() {
    let board = Board::new("bunzzle", &TWO, 2).expect("valid");
    assert_eq!(board.cores(), 2);
    assert!(board.slab(2).is_none());
    let slab = board.slab(1).expect("core 1");
    assert_eq!(slab.published(), None);
    slab.set(0, 7);
    slab.set(5, 9);
    slab.publish(0);
    assert_eq!(slab.published(), Some(0));
    assert_eq!(slab.get(0), Some(7));
    assert_eq!(slab.get(5), None);
    slab.publish(u64::MAX);
    assert_eq!(slab.published(), Some(u64::MAX - 1));
    assert_eq!(board.slab(0).expect("core 0").published(), None);
}

#[test]
fn readers_see_values_published_before_the_stamp() {
    let board = Arc::new(Board::new("bunzzle", &TWO, 1).expect("valid"));
    let writer = {
        let board = Arc::clone(&board);
        thread::spawn(move || {
            let slab = board.slab(0).expect("core 0");
            for round in 1..=20_000u64 {
                slab.set(0, round);
                slab.set(1, round);
                slab.publish(round);
            }
        })
    };
    let slab = board.slab(0).expect("core 0");
    while !writer.is_finished() {
        if let Some(stamp) = slab.published() {
            assert!(slab.get(0).expect("value") >= stamp);
            assert!(slab.get(1).expect("value") >= stamp);
        }
    }
    writer.join().expect("writer");
    assert_eq!(slab.get(0), Some(20_000));
}
