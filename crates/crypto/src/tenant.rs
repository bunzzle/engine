use aws_lc_rs::agreement::{PrivateKey, X25519};

use crate::{DataKey, Error, Prk, Secret};

pub struct Tenant(Prk);

impl Tenant {
    pub fn new(key: &Secret<32>) -> Self {
        Self(Prk::from_secret(key))
    }

    pub fn data_secret(&self, generation: u32, version: u8) -> Secret<32> {
        self.0
            .expand(&[b"data", &generation.to_le_bytes(), &[version]])
    }

    pub fn data_key(&self, generation: u32, version: u8) -> DataKey {
        DataKey::new(&self.data_secret(generation, version), version)
    }

    pub fn hash_key(&self, generation: u32) -> Secret<16> {
        self.0.expand(&[b"hash", &generation.to_le_bytes()])
    }

    pub fn return_key(&self, generation: u32) -> Secret<16> {
        self.0.expand(&[b"return", &generation.to_le_bytes()])
    }

    pub fn dkim_key(&self, generation: u32, version: u8) -> DataKey {
        let key = self
            .0
            .expand::<32>(&[b"dkim", &generation.to_le_bytes(), &[version]]);
        DataKey::new(&key, version)
    }

    pub fn hook_secret(&self, generation: u32, hook: u32, version: u8) -> Secret<32> {
        self.0.expand(&[
            b"hook",
            &generation.to_le_bytes(),
            &hook.to_le_bytes(),
            &[version],
        ])
    }
}

pub fn next_day(state: &Secret<32>) -> Secret<32> {
    Prk::from_secret(state).expand(&[b"next"])
}

pub fn ratchet(state: &Secret<32>, days: u32) -> Secret<32> {
    let mut current = state.copy();
    for _ in 0..days {
        current = next_day(&current);
    }
    current
}

pub fn day_secret(state: &Secret<32>) -> Secret<32> {
    Prk::from_secret(state).expand(&[b"seed"])
}

pub fn search_key(state: &Secret<32>, tenant: u32, generation: u32, day: u32) -> Secret<16> {
    Prk::from_secret(state).expand(&[
        b"search",
        &tenant.to_le_bytes(),
        &generation.to_le_bytes(),
        &day.to_le_bytes(),
    ])
}

pub fn day_public(secret: &Secret<32>) -> Result<[u8; 32], Error> {
    let key = PrivateKey::from_private_key(&X25519, secret.expose()).map_err(|_| Error::Key)?;
    let public = key.compute_public_key().map_err(|_| Error::Key)?;
    public.as_ref().try_into().map_err(|_| Error::Key)
}

#[cfg(test)]
mod tests {
    use super::{Tenant, day_public, day_secret, next_day, ratchet, search_key};
    use crate::Secret;

    #[test]
    fn ratchet_steps_match_single_moves() {
        let start = Secret::new([5; 32]);
        let two = next_day(&next_day(&start));
        assert!(ratchet(&start, 2) == two);
        assert!(ratchet(&start, 0) == start);
        assert!(ratchet(&start, 1) != start);
    }

    #[test]
    fn days_have_distinct_keys() {
        let start = Secret::new([5; 32]);
        let today = day_public(&day_secret(&start)).expect("public");
        let tomorrow = day_public(&day_secret(&next_day(&start))).expect("public");
        assert_ne!(today, tomorrow);
        assert!(day_secret(&start) != start);
    }

    #[test]
    fn known_answer() {
        use crate::seal::tests::hex;
        let state = Secret::new([5; 32]);
        assert_eq!(
            hex(next_day(&state).expose()),
            "7c0aeff233bfce934c1ff1cd9b4f4e2ac0d24a975b57d6ffa385607639985ace"
        );
        assert_eq!(
            hex(day_secret(&state).expose()),
            "c3526015097c11f50b929e0bb36e25cb159d51e67b413ffa03548c8bb1193625"
        );
        assert_eq!(
            hex(&day_public(&day_secret(&state)).expect("public")),
            "4ff67bbdfdc27c0c38d244a16068aebd90f1f67d6d1461264559881c00c9a553"
        );
        let tenant = Tenant::new(&Secret::new([6; 32]));
        let salt = Secret::new([9; 16]);
        assert_eq!(
            hex(&tenant.dkim_key(1, 2).seal_salted(&salt, b"l", b"x")),
            "01020909090909090909090909090909090966e7e02f90d6036e2516e9cffc8c7ded9f"
        );
        assert_eq!(
            hex(&tenant.data_key(1, 2).seal_salted(&salt, b"l", b"x")),
            "010209090909090909090909090909090909426a9010bf18588b98810316c1536395d0"
        );
        assert_eq!(
            hex(tenant.hash_key(1).expose()),
            "bd7f2bae6ff8c12b0d35b5e12a9ebeb7"
        );
        assert_eq!(
            hex(tenant.return_key(1).expose()),
            "586d6e5b4584547bb771be1722872632"
        );
        assert_eq!(
            hex(tenant.hook_secret(1, 3, 2).expose()),
            "63ad8d3fdf512fd218ab2222b41a185feff0894e9e8db302888518a43c93335e"
        );
    }

    #[test]
    fn search_key_known_answer() {
        use crate::seal::tests::hex;
        let state = Secret::new([5; 32]);
        assert_eq!(
            hex(search_key(&state, 4, 2, 20_000).expose()),
            "0ae4b4d6abc65be9327538602db7bb87"
        );
    }

    #[test]
    fn search_keys_differ_by_tenant_generation_day_and_state() {
        let state = Secret::new([5; 32]);
        let key = search_key(&state, 4, 2, 20_000);
        assert!(key == search_key(&state, 4, 2, 20_000));
        assert!(key != search_key(&state, 5, 2, 20_000));
        assert!(key != search_key(&state, 4, 3, 20_000));
        assert!(key != search_key(&state, 4, 2, 20_001));
        assert!(key != search_key(&next_day(&state), 4, 2, 20_000));
        assert_ne!(key.expose()[..], day_secret(&state).expose()[..16]);
    }

    #[test]
    fn tenant_keys_depend_on_generation() {
        let tenant = Tenant::new(&Secret::new([6; 32]));
        assert!(tenant.hash_key(1) != tenant.hash_key(2));
        let sealed = tenant.data_key(1, 1).seal(b"l", b"x").expect("seals");
        assert!(tenant.data_key(2, 1).open(b"l", &sealed).is_err());
        assert!(tenant.dkim_key(1, 1).open(b"l", &sealed).is_err());
        assert_eq!(tenant.dkim_key(1, 2).version(), 2);
        let hook = tenant.hook_secret(1, 3, 1);
        assert!(hook == tenant.hook_secret(1, 3, 1));
        assert!(hook != tenant.hook_secret(2, 3, 1));
        assert!(hook != tenant.hook_secret(1, 4, 1));
        assert!(hook != tenant.hook_secret(1, 3, 2));
        assert!(hook != tenant.data_secret(1, 1));
        assert_eq!(
            tenant.data_key(1, 1).open(b"l", &sealed).expect("opens"),
            b"x"
        );
    }
}
