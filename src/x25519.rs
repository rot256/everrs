use rand_core::CryptoRng;
use rand_core::RngCore;
use zeroize::Zeroize;

use super::bind::{EverCrypt_Curve25519_ecdh, EverCrypt_Curve25519_secret_to_public};

pub struct PublicKey {
    point: [u8; 32],
}

pub struct SecretKey {
    scalar: [u8; 32],
}

pub struct SharedSecret {
    shared: [u8; 32],
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.shared.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.scalar.zeroize()
    }
}

fn clamp_scalar(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.shared
    }
}

impl SecretKey {
    pub fn new<T>(csprng: &mut T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        let mut sk = SecretKey { scalar: [0; 32] };
        csprng.fill_bytes(&mut sk.scalar);
        clamp_scalar(&mut sk.scalar);
        sk
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.scalar
    }

    pub fn diffie_hellman(&self, their: &PublicKey) -> SharedSecret {
        let mut shared_secret = SharedSecret { shared: [0; 32] };
        unsafe {
            EverCrypt_Curve25519_ecdh(
                shared_secret.shared.as_mut_ptr(),
                self.scalar.as_ptr(),
                their.point.as_ptr(),
            );
        }
        shared_secret
    }
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.point
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(sk: [u8; 32]) -> SecretKey {
        let mut sk = SecretKey { scalar: sk };
        clamp_scalar(&mut sk.scalar); // this is a no-op on well-formed private keys
        sk
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(pk: [u8; 32]) -> PublicKey {
        PublicKey { point: pk }
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> PublicKey {
        let mut pk = PublicKey { point: [0; 32] };
        unsafe {
            EverCrypt_Curve25519_secret_to_public(
                pk.point.as_mut_ptr(), // public point
                sk.scalar.as_ptr(),    // secret scalar
            );
        }
        pk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn diffie_hellman_test(skb1: [u8; 32], skb2: [u8; 32]) {
            let sk1 = SecretKey::from(skb1);
            let sk2 = SecretKey::from(skb2);
            let pk1 = PublicKey::from(&sk1);
            let pk2 = PublicKey::from(&sk2);
            assert_eq!(
                sk1.diffie_hellman(&pk2).as_bytes(),
                sk2.diffie_hellman(&pk1).as_bytes(),
                "diffie-hellman computation does not commute"
            );
        }
    }
}
