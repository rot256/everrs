#[link(name = "libevercrypt")]
extern {
    fn EverCrypt_Chacha20Poly1305_aead_encrypt(
        k: *const cty::uint8_t,
        n1: *const cty::uint8_t,
        aadlen: cty::uint32_t,
        aad: *const cty::uint8_t,
        mlen: cty::uint32_t,
        m: *const cty::uint8_t,
        cipher: *mut cty::uint8_t,
        tag: *mut cty::uint8_t
    );
}
