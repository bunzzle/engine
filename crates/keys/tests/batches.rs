use std::rc::Rc;
use std::time::Duration;

use crypto::{BatchKey, Secret, Tenant, TenantKeys, Wrap, aad, day_public, open_batch};
use keys::{BatchSettings, Batches, Working};
use rt::sim::{Config, SimDriver};
use rt::{Runtime, now};

const DAY: u32 = 20_833;

fn run<T: 'static>(future: impl Future<Output = T> + 'static) -> T {
    Runtime::new(Rc::new(SimDriver::new(1, Config::default()))).block_on(future)
}

fn secret(tenant: u32, day: u32) -> Secret<32> {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&tenant.to_le_bytes());
    bytes[4..8].copy_from_slice(&day.to_le_bytes());
    Secret::new(bytes)
}

fn working(tenant: u32, generation: u32, day: u32) -> Working {
    let root = Tenant::new(&Secret::new([1; 32]));
    Working {
        keys: TenantKeys::derive(tenant, generation, &root, 1),
        day,
        oldest: DAY,
        today: day_public(&secret(tenant, day)).expect("public"),
        tomorrow: day_public(&secret(tenant, day + 1)).expect("public"),
    }
}

fn same_key(a: &BatchKey, b: &BatchKey) -> bool {
    let message = [7; 16];
    let aad = aad(4, 1, &message, 0, 1);
    let sealed = a.record(&message, 0, 1).seal_one(&aad, b"mail");
    b.record(&message, 0, 1).open_one(&aad, &sealed).is_ok()
}

#[test]
fn a_batch_rotates_after_its_seals_its_day_and_its_age() {
    run(async {
        let mut batches = Batches::new(BatchSettings::default());
        let today = working(4, 1, DAY);
        let start = now();
        let first = batches.seal(&today, 2, 100, start).expect("seal");
        for n in 1..1_024 {
            let again = batches.seal(&today, 2, 100 + n, start).expect("seal");
            assert_eq!(again.id, first.id);
        }
        let full = batches.seal(&today, 2, 2_000, start).expect("seal");
        assert_eq!(full.id, 2_000);
        assert_eq!(batches.stats().full, 1);
        let replaced = batches.cached(4, 1, 2, 100).expect("replaced batch cached");
        assert!(same_key(&replaced, &first.key));
        let next_day = batches
            .seal(&working(4, 1, DAY + 1), 2, 3_000, start)
            .expect("seal");
        assert_eq!((next_day.id, next_day.day), (3_000, DAY + 1));
        assert_eq!(batches.stats().day, 1);
        let other_shard = batches.seal(&today, 3, 4_000, start).expect("seal");
        assert_eq!(other_shard.id, 4_000);
        assert_eq!(batches.open_count(), 2);
        let later = start + Duration::from_secs(60);
        batches.sweep(later);
        assert_eq!(batches.open_count(), 0);
        assert_eq!(batches.stats().aged, 2);
        let found = batches.cached(4, 1, 2, 3_000).expect("closed batch cached");
        assert!(same_key(&found, &next_day.key));
        let fresh = batches
            .seal(&working(4, 1, DAY + 1), 2, 5_000, later)
            .expect("seal");
        assert_eq!(fresh.id, 5_000);
    });
}

#[test]
fn the_wrap_opens_to_the_batch_key_with_the_day_secret() {
    run(async {
        let mut batches = Batches::new(BatchSettings::default());
        let batch = batches
            .seal(&working(4, 1, DAY), 2, 77, now())
            .expect("seal");
        let wrap = Wrap::decode(&batch.wrap).expect("wrap");
        assert_eq!((wrap.day, wrap.shard, wrap.generation), (DAY, 2, 1));
        let opened = open_batch(&secret(4, DAY), 4, 77, &wrap).expect("open");
        assert!(same_key(&BatchKey::new(&opened), &batch.key));
        assert!(open_batch(&secret(4, DAY), 4, 78, &wrap).is_err());
        assert!(open_batch(&secret(5, DAY), 5, 77, &wrap).is_err());
    });
}

#[test]
fn cached_keys_answer_only_their_own_tenant_and_generation() {
    run(async {
        let mut batches = Batches::new(BatchSettings {
            cache: 2,
            ..BatchSettings::default()
        });
        let batch = batches
            .seal(&working(4, 1, DAY), 2, 77, now())
            .expect("seal");
        assert!(batches.cached(4, 1, 2, 77).is_some());
        assert!(batches.cached(5, 1, 2, 77).is_none());
        assert!(batches.cached(4, 2, 2, 77).is_none());
        assert!(batches.cached(4, 1, 3, 77).is_none());
        for id in 1..10 {
            batches.remember(9, 1, 2, id, Rc::clone(&batch.key));
        }
        assert!(batches.cached(4, 1, 2, 77).is_some(), "open batch evicted");
        batches.remember(5, 1, 6, 900, Rc::clone(&batch.key));
        assert!(batches.cached(4, 1, 6, 900).is_none());
        assert!(batches.stats().mismatched >= 3);
        batches.forget(4, 1);
        assert!(batches.cached(4, 1, 2, 77).is_none());
        assert_eq!(batches.open_count(), 0);
    });
}

#[test]
fn a_batch_rotates_on_its_own_age_between_sweeps_and_keeps_its_cache_owner() {
    run(async {
        let mut batches = Batches::new(BatchSettings::default());
        let today = working(4, 1, DAY);
        let start = now();
        let first = batches.seal(&today, 2, 100, start).expect("seal");
        let almost = start + Duration::from_millis(59_900);
        assert_eq!(batches.seal(&today, 2, 101, almost).expect("seal").id, 100);
        let aged = batches
            .seal(&today, 2, 102, start + Duration::from_secs(60))
            .expect("seal");
        assert_eq!(aged.id, 102);
        assert_eq!(batches.stats().aged, 1);
        batches.remember(5, 1, 2, 100, Rc::clone(&aged.key));
        let kept = batches.cached(4, 1, 2, 100).expect("owner kept");
        assert!(same_key(&kept, &first.key));
        assert!(batches.cached(5, 1, 2, 100).is_none());
        assert!(batches.stats().mismatched >= 2);
    });
}
