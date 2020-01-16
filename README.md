<img src="icon.png" align="right" height="350" width="350"/>

![CI Status](https://github.com/rot256/everrs/workflows/Rust/badge.svg)

# Everrs

Everrs provides safe bindings for the formally verified [HACL*/EverCrypt](https://github.com/project-everest/hacl-star) crypto library:
EverCrypt formally verifies that the implementation is consistent with the specification
and that the implementations are constant time.

Despite these guarantees the performance of EverCrypt is very competitive.

**Warning:** Everrs is still early work-in-progress and the API is still subject to change.

## Primitives

Eventually bindings for all EverCrypt primitives will be provided.
Currently the following primitives are supported:

- X25519
- ChaCha20Poly1305

For X25519, the API is (almost) a drop-in alternative to [x25519-dalek](https://github.com/dalek-cryptography/x25519-dalek) library.

Below is a simple example of how to encrypt and authenticate a buffer using Everrs:

```rust
use everrs::chacha20poly1305::{seal, open};

...

let mut ct : Vec<u8> = vec![0; pt.len()];
let mut tag : [u8; 16] = [0; 16];
seal(&key, &nonce, &ad[..], &pt, &mut ct, &mut tag);
open(&key, &nonce, &ad[..], &mut ptt, &ct, &tag).expect("authentication failure");
```

## API Philosophy

Most (all?) cryptographic functions are pure functions,
hence there are essentially two classes of errors/failures:

1. The developer provides invalid arguments (essentially the type system is not sufficiently expressive to stop him),
e.g. the size of the result buffer is insuffient to hold the decrypted ciphertext, or a key is to short for the scheme.
2. Failures from authentication failures.

Everrs adopts the philosphy that errors should be meaningful signals at runtime, not indicators of bad programming.
Hence we believe that the first type of error is best dealt with by causing a 'panic',
rather than return a 'Result' which could potentially be handled,
but would never occur when the library is used correctly.
This is consistent with e.g. the behavior when accessing elements out-of-bounds in slices.
