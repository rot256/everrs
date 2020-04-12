#![no_std]
#![cfg_attr(feature = "unstable", feature(test))]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
#[cfg(feature = "unstable")]
extern crate test;

mod bind;

pub mod chacha20poly1305;
pub mod x25519;
