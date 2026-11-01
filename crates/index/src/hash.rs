pub fn siphash128(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d ^ 0xee,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let (words, tail) = data.as_chunks::<8>();
    for word in words {
        compress(&mut v, u64::from_le_bytes(*word));
    }
    let mut last = [0; 8];
    last[..tail.len()].copy_from_slice(tail);
    compress(
        &mut v,
        u64::from_le_bytes(last) | ((data.len() as u64 & 0xff) << 56),
    );
    v[2] ^= 0xee;
    for _ in 0..4 {
        round(&mut v);
    }
    let low = v[0] ^ v[1] ^ v[2] ^ v[3];
    v[1] ^= 0xdd;
    for _ in 0..4 {
        round(&mut v);
    }
    let high = v[0] ^ v[1] ^ v[2] ^ v[3];
    let mut out = [0; 16];
    out[..8].copy_from_slice(&low.to_le_bytes());
    out[8..].copy_from_slice(&high.to_le_bytes());
    out
}

fn compress(v: &mut [u64; 4], m: u64) {
    v[3] ^= m;
    round(v);
    round(v);
    v[0] ^= m;
}

fn round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}
