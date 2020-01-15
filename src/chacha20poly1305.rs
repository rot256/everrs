use super::bind::{
    EverCrypt_Chacha20Poly1305_aead_decrypt, EverCrypt_Chacha20Poly1305_aead_encrypt,
};

/// Decrypt & authenticate a buffer with ChaCha20Poly1305
///
/// # Arguments
///
/// - `key`: 256-bit key.
/// - `nonce`: 192-bit nonce (unique for every message).
/// - `ad`: Buffer of associated data.
/// - `pt`: The plaintext buffer.
/// - `ct`: The resulting ciphertext buffer.
/// - `tag`: The buffer to hold the resulting authentication tag.
///
/// # Notes
///
/// The AD must be less than 2^32 bytes.
/// The plaintext buffer must be less than 2^32 bytes.
/// The ciphertext buffer must be at least the size of the plaintext buffer.
///
/// # Result
///
/// Returns a Result with Err indicating authentication failure.
/// Checking the Result is crucial for security.
#[must_use = "authentication failure must be handled"]
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: &[u8],
    pt: &mut [u8],
    ct: &[u8],
    tag: &[u8; 16],
) -> Result<(), ()> {
    assert!(ct.len() <= pt.len());
    assert!(ct.len() <= u32::max_value() as usize);
    assert!(ad.len() <= u32::max_value() as usize);
    let ok = unsafe {
        EverCrypt_Chacha20Poly1305_aead_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ad.len() as cty::uint32_t,
            ad.as_ptr(),
            ct.len() as cty::uint32_t,
            pt.as_mut_ptr(),
            ct.as_ptr(),
            tag.as_ptr(),
        )
    };
    if ok == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// Decrypt & authenticate a buffer with ChaCha20Poly1305 in-place
///
/// # Arguments
///
/// - `key`: 256-bit key.
/// - `nonce`: 192-bit nonce (unique for every message).
/// - `ad`: Buffer of associated data.
/// - `msg`: The ciphertext (and resulting plaintext) buffer.
/// - `tag`: The buffer holding the authentication tag.
///
/// # Notes
///
/// The tag buffer must be exactly 16 bytes long.
/// The nonce buffer must be exactly 24 bytes long.
/// The associated data must be less than 2^32 bytes.
/// The plaintext buffer must be less than 2^32 bytes.
///
/// # Result
///
/// Returns a Result with Err indicating authentication failure.
/// Checking the Result is crucial for security.
#[must_use = "authentication failure must be handled"]
pub fn open_inplace(
    key: &[u8; 32],
    nonce: &[u8],
    ad: &[u8],
    msg: &mut [u8],
    tag: &[u8],
) -> Result<(), ()> {
    assert!(ad.len() <= u32::max_value() as usize);
    assert!(msg.len() <= u32::max_value() as usize);
    assert_eq!(nonce.len(), 24, "nonce must be 24 bytes long");
    assert_eq!(tag.len(), 16, "tag buffer must be 16 bytes");
    let ok = unsafe {
        EverCrypt_Chacha20Poly1305_aead_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ad.len() as cty::uint32_t,
            ad.as_ptr(),
            msg.len() as cty::uint32_t,
            msg.as_mut_ptr(),
            msg.as_ptr(),
            tag.as_ptr(),
        )
    };
    if ok == 0 {
        Ok(())
    } else {
        Err(())
    }
}

/// Encrypt a buffer with ChaCha20Poly1305
///
/// # Arguments
///
/// - `key`: 256-bit key
/// - `nonce`: 192-bit nonce (unique for every message)
/// - `ad`: Buffer of associated data
/// - `pt`: The plaintext buffer
/// - `ct`: The resulting ciphertext buffer
/// - `tag`: The buffer to hold the resulting authentication tag
///
/// # Notes
///
/// The AD must be less than 2^32 bytes.
/// The plaintext buffer must be less than 2^32 bytes.
/// The ciphertext buffer must be at least the size of the plaintext buffer.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; 16],
) {
    assert!(ct.len() >= pt.len());
    assert!(pt.len() <= u32::max_value() as usize);
    assert!(ad.len() <= u32::max_value() as usize);
    unsafe {
        EverCrypt_Chacha20Poly1305_aead_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ad.len() as cty::uint32_t,
            ad.as_ptr(),
            pt.len() as cty::uint32_t,
            pt.as_ptr(),
            ct.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
    }
}

/// Encrypt a buffer in-place with ChaCha20Poly1305
///
/// # Arguments
///
/// - `key`: 256-bit key
/// - `nonce`: 192-bit nonce (unique for every message)
/// - `ad`: Buffer of associated data
/// - `msg`: The message buffer to encrypt (in-place)
/// - `tag`: The buffer to hold the resulting authentication tag
///
/// # Usage
///
/// A continous region of memory can be encrypted and the tag
/// appended/preprended by using the `std::slice::split_at_mut`
/// function to obtain two disjoint mutable slices.
///
/// # Notes
///
/// The AD must be less than 2^32 bytes.
/// The message buffer must be less than 2^32 bytes.
/// The tag buffer must be exactly 16 bytes.
pub fn seal_inplace(key: &[u8; 32], nonce: &[u8], ad: &[u8], msg: &mut [u8], tag: &mut [u8]) {
    assert!(ad.len() <= u32::max_value() as usize);
    assert!(msg.len() <= u32::max_value() as usize);
    assert_eq!(nonce.len(), 24, "nonce must be 24 bytes long");
    assert_eq!(tag.len(), 16, "tag buffer must be 16 bytes");
    unsafe {
        EverCrypt_Chacha20Poly1305_aead_encrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ad.len() as cty::uint32_t,
            ad.as_ptr(),
            msg.len() as cty::uint32_t,
            msg.as_ptr(),
            msg.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::vec::Vec;
    use test::Bencher;

    proptest! {
        #[test]
        fn seal_test(pt: Vec<u8>, ad: Vec<u8>, key: [u8; 32], nonce: [u8; 24]) {
            let mut ct : Vec<u8> = vec![0; pt.len()];
            let mut ptt : Vec<u8> = vec![0; pt.len()];
            let mut tag : [u8; 16] = [0; 16];
            seal(&key, &nonce, &ad[..], &pt, &mut ct, &mut tag);
            open(&key, &nonce, &ad[..], &mut ptt, &ct, &tag).unwrap();
            assert_eq!(&ptt[..], &pt[..], "open \\circ seal != id");
        }

        #[test]
        fn seal_test_inplace(pt: Vec<u8>, ad: Vec<u8>, key: [u8; 32], nonce: [u8; 24]) {
            let mut ptt : Vec<u8> = pt.clone();

            // make space for tag in the same buffer
            ptt.extend(&[0u8; 16]);

            // split into plaintext and tag part
            let (pb, tb) = ptt.split_at_mut(pt.len());

            // encrypt / decrypt in-place
            seal_inplace(&key, &nonce, &ad[..], pb, tb);
            open_inplace(&key, &nonce, &ad[..], pb, tb).unwrap();
            assert_eq!(&pb[..], &pt[..], "open_inplace \\circ seal_inplace != id");
        }
    }

    #[bench]
    fn bench_seal(b: &mut Bencher) {
        let key: [u8; 32] = [1; 32];
        let nonce: [u8; 24] = [0; 24];
        let ad: [u8; 0] = [];
        let mut tag: [u8; 16] = [0; 16];
        let mut pt: Vec<u8> = vec![0; 1024 * 1024];
        b.iter(|| {
            seal_inplace(&key, &nonce, &ad[..], &mut pt[..], &mut tag[..]);
        });
    }
}
