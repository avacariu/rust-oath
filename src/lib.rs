#![feature(core, old_io)]

extern crate crypto;

// TODO: find out where this function is going to be once old_io is gone
use std::old_io::extensions::{u64_to_be_bytes, u64_from_be_bytes};
use std::num::Int;

use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;

fn dynamic_truncation(hs: &[u8]) -> u64 {
    let offset_bits = (hs[19] & 0xf) as usize;
    let p = u64_from_be_bytes(hs, offset_bits, 4);

    p & 0x7fffffff
}

pub fn hotp(key: &[u8], counter: u64, digits: usize) -> u64 {
    let mut hmac = Hmac::new(Sha1::new(), key);
    u64_to_be_bytes(counter, 8, |bytes| {
        hmac.input(bytes)
    });
    let result = hmac.result();
    let hs = result.code();

    dynamic_truncation(hs) % 10.pow(digits)
}

#[test]
fn it_works() {
    assert_eq!(hotp(b"\xff", 23, 6), 330795);
}
