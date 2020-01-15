#[link(name = "evercrypt", kind = "static")]
extern "C" {
    pub(crate) fn EverCrypt_Chacha20Poly1305_aead_encrypt(
        k: *const cty::uint8_t,
        n1: *const cty::uint8_t,
        aadlen: cty::uint32_t,
        aad: *const cty::uint8_t,
        mlen: cty::uint32_t,
        m: *const cty::uint8_t,
        cipher: *mut cty::uint8_t,
        tag: *mut cty::uint8_t,
    );

    pub(crate) fn EverCrypt_Chacha20Poly1305_aead_decrypt(
        k: *const cty::uint8_t,
        n1: *const cty::uint8_t,
        aadlen: cty::uint32_t,
        aad: *const cty::uint8_t,
        mlen: cty::uint32_t,
        m: *mut cty::uint8_t,
        cipher: *const cty::uint8_t,
        tag: *const cty::uint8_t,
    ) -> cty::uint32_t;

    pub(crate) fn EverCrypt_Curve25519_secret_to_public(
        r#pub: *mut cty::uint8_t,
        r#priv: *const cty::uint8_t,
    );

    pub(crate) fn EverCrypt_Curve25519_ecdh(
        shared: *mut cty::uint8_t,
        my_priv: *const cty::uint8_t,
        their_pub: *const cty::uint8_t,
    ) -> cty::c_int;
}
