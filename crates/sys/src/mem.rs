use std::sync::atomic::{Ordering, compiler_fence};

#[allow(unsafe_code)]
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        let byte: *mut u8 = byte;
        // SAFETY: `byte` comes from a live exclusive reference, so it is valid and aligned for a write.
        unsafe { byte.write_volatile(0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::wipe;

    #[test]
    fn wipes_every_byte() {
        let mut bytes = [0xa5u8; 37];
        wipe(&mut bytes);
        assert_eq!(bytes, [0; 37]);
    }
}
