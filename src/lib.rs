#![feature(test)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
extern crate test;

mod bind;

pub mod chacha20poly1305;
pub mod x25519;
