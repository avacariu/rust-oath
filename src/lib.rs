#![feature(core, old_io)]

extern crate crypto;
extern crate "rustc-serialize" as rustc_serialize;

// TODO: find out where this function is going to be once old_io is gone
use std::old_io::extensions::{u64_to_be_bytes, u64_from_be_bytes};
use std::num::Int;
use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use rustc_serialize::hex::FromHex;

fn dynamic_truncation(hs: &[u8]) -> u64 {
    let offset_bits = (hs[19] & 0xf) as usize;
    let p = u64_from_be_bytes(hs, offset_bits, 4);

    p & 0x7fffffff
}

pub fn hotp_custom<D: Digest>(key: &[u8], counter: u64, digits: usize,
                              hash: D) -> u64 {
    let mut hmac = Hmac::new(hash, key);
    u64_to_be_bytes(counter, 8, |bytes| {
        hmac.input(bytes)
    });
    let result = hmac.result();
    let hs = result.code();

    dynamic_truncation(hs) % 10.pow(digits)
}

pub fn hotp_raw(key: &[u8], counter: u64, digits: usize) -> u64 {
    let hash = Sha1::new();
    hotp_custom(key, counter, digits, hash)
}

pub fn hotp(key: &str, counter: u64, digits: usize) -> Result<u64, &str> {
    match key.from_hex() {
        Ok(bytes) => Ok(hotp_raw(bytes.as_slice(), counter, digits)),
        Err(_) => Err("Unable to parse hex.")
    }
}

#[test]
fn it_works() {
    assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);
    assert_eq!(hotp("ff", 23, 6).unwrap(), 330795);
    assert_eq!(hotp_custom(b"\xff", 23, 6, Sha1::new()), 330795);
}
