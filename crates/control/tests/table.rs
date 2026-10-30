use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use control::{Limits, Note, Object, Pool, Snapshot, State, Table, Tenant, Update, broadcast};
use rt::sim::{Config, Machine, SimDriver, Stalls, check};
use rt::{Mesh, yield_now};

const CORES: u16 = 4;

fn tenant(id: u32, generation: u32) -> Object {
    Object::Tenant(Tenant {
        id,
        generation,
        state: State::Active,
        default_pool: 1,
        pools: vec![1],
        limits: Limits::default(),
    })
}

fn update(version: u64, object: Object) -> Update {
    Update { version, object }
}

#[test]
fn updates_apply_in_version_order_after_the_snapshot() {
    let mut table = Table::default();
    table.apply(update(4, tenant(1, 4)));
    table.apply(update(3, tenant(1, 3)));
    assert!(!table.loaded());
    assert_eq!(table.tenant(1), None);
    table.load(Snapshot {
        version: 2,
        objects: vec![
            tenant(1, 2),
            Object::Pool(Pool {
                id: 1,
                addresses: Vec::new(),
            }),
        ],
    });
    assert_eq!(table.version(), 4);
    assert_eq!(table.tenant(1).map(|t| t.generation), Some(4));
    assert!(table.pool(1).is_some());
    table.apply(update(6, tenant(2, 6)));
    assert_eq!(table.version(), 4);
    assert_eq!(table.waiting(), 1);
    assert_eq!(table.tenant(2), None);
    table.apply(update(5, tenant(1, 5)));
    assert_eq!(table.version(), 6);
    assert_eq!(table.waiting(), 0);
    assert_eq!(table.tenant(1).map(|t| t.generation), Some(5));
    assert_eq!(table.tenant(2).map(|t| t.generation), Some(6));
    table.apply(update(5, tenant(1, 99)));
    table.apply(update(2, tenant(1, 98)));
    assert_eq!(table.tenant(1).map(|t| t.generation), Some(5));
    assert_eq!(table.waiting(), 0);
}

#[test]
fn updates_older_than_the_snapshot_are_dropped() {
    let mut table = Table::default();
    table.apply(update(1, tenant(1, 1)));
    table.apply(update(3, tenant(1, 3)));
    table.load(Snapshot {
        version: 3,
        objects: vec![tenant(1, 3)],
    });
    assert_eq!(table.waiting(), 0);
    assert_eq!(table.version(), 3);
    assert_eq!(table.tenants().count(), 1);
    assert_eq!(table.pools().count(), 0);
}

fn spread(seed: u64) {
    let sim = Rc::new(SimDriver::new(seed, Config::default()));
    let stalls = Stalls {
        per_mille: 50,
        max: Duration::from_millis(5),
    };
    let machine = Machine::new(Rc::clone(&sim), usize::from(CORES), stalls);
    let mesh = Arc::new(Mesh::<Note>::new(CORES));
    let mut tasks = Vec::new();
    for core in 0..CORES {
        let ends = mesh.take(core).expect("ends");
        let driver = Rc::clone(&sim);
        tasks.push(machine.spawn_on(usize::from(core), async move {
            let table = Rc::new(RefCell::new(Table::default()));
            let applied = Rc::clone(&table);
            let (peers, done) = ends.start(move |_, note| applied.borrow_mut().take(note));
            if core == 0 {
                let snapshot = Snapshot {
                    version: 7,
                    objects: vec![tenant(1, 7)],
                };
                broadcast(&peers, CORES, &Note::Snapshot(snapshot));
                for version in 8..=60 {
                    let id = u32::try_from(driver.random() % 5).expect("small") + 1;
                    let generation = u32::try_from(version).expect("small");
                    broadcast(
                        &peers,
                        CORES,
                        &Note::Update(update(version, tenant(id, generation))),
                    );
                    if driver.random().is_multiple_of(3) {
                        yield_now().await;
                    }
                }
            }
            peers.close();
            done.await;
            let table = table.borrow();
            let tenants: Vec<(u32, u32)> = table.tenants().map(|t| (t.id, t.generation)).collect();
            (table.version(), table.waiting(), tenants)
        }));
    }
    let tables = machine.block_on(0, async move {
        let mut tables = Vec::new();
        for task in tasks {
            tables.push(task.await);
        }
        tables
    });
    assert_eq!(tables[0].0, 60);
    assert_eq!(tables[0].1, 0);
    assert!(tables.iter().all(|t| *t == tables[0]), "{tables:?}");
}

#[test]
fn every_core_ends_with_the_same_table() {
    check(0..20, spread);
}
