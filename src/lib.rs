extern crate crypto;
extern crate rustc_serialize;
extern crate time;

use crypto::sha1::Sha1;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use rustc_serialize::hex::FromHex;

pub fn from_hex(data: &str) -> Result<Vec<u8>, &str> {
    match data.from_hex() {
        Ok(d) => Ok(d),
        Err(_) => Err("Unable to decode hex")
    }
}

fn u64_from_be_bytes_4(bytes: &[u8], start: usize) -> u64 {
    let mut val = 0u64;

    val += (bytes[start]   as u64) << ((3 * 8) as u64);
    val += (bytes[start+1] as u64) << ((2 * 8) as u64);
    val += (bytes[start+2] as u64) << ((1 * 8) as u64);
    val += (bytes[start+3] as u64) << ((0 * 8) as u64);

    val
}

fn u64_to_be_bytes_8(data: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.push((data >> 56) as u8);
    v.push((data >> 48) as u8);
    v.push((data >> 40) as u8);
    v.push((data >> 32) as u8);
    v.push((data >> 24) as u8);
    v.push((data >> 16) as u8);
    v.push((data >> 8) as u8);
    v.push(data as u8);

    v
}

fn dynamic_truncation(hs: &[u8]) -> u64 {
    let offset_bits = (hs[19] & 0xf) as usize;
    let p = u64_from_be_bytes_4(hs, offset_bits);

    p & 0x7fffffff
}

pub fn hotp_custom<D: Digest>(key: &[u8], counter: u64, digits: u32,
                              hash: D) -> u64 {
    let mut hmac = Hmac::new(hash, key);
    let bytes = u64_to_be_bytes_8(counter);
    hmac.input(bytes.as_ref());
    let result = hmac.result();
    let hs = result.code();

    dynamic_truncation(hs) % 10_u64.pow(digits)
}

pub fn hotp_raw(key: &[u8], counter: u64, digits: u32) -> u64 {
    let hash = Sha1::new();
    hotp_custom(key, counter, digits, hash)
}

pub fn hotp(key: &str, counter: u64, digits: u32) -> Result<u64, &str> {
    match key.from_hex() {
        Ok(bytes) => Ok(hotp_raw(bytes.as_ref(), counter, digits)),
        Err(_) => Err("Unable to parse hex.")
    }
}

pub fn totp_custom<D: Digest>(key: &[u8], digits: u32, epoch: u64,
                              time_step: u64, current_time: u64,
                              hash: D) -> u64 {
    let counter = (current_time - epoch) / time_step;
    hotp_custom(key, counter, digits, hash)
}

pub fn totp_raw(key: &[u8], digits: u32, epoch: u64, time_step: u64) -> u64 {
    let hash = Sha1::new();
    let current_time = time::get_time();
    totp_custom(key, digits, epoch, time_step, current_time.sec as u64, hash)
}

pub fn totp(key: &str, digits: u32, epoch: u64,
            time_step: u64) -> Result<u64, &str> {
    match key.from_hex() {
        Ok(bytes) => Ok(totp_raw(bytes.as_ref(), digits, epoch, time_step)),
        Err(_) => Err("Unable to parse hex.")
    }
}

#[test]
fn test_hotp() {
    use crypto::sha2::Sha256;

    assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);
    assert_eq!(hotp("ff", 23, 6).unwrap(), 330795);
    assert_eq!(hotp_custom(b"\xff", 23, 6, Sha1::new()), 330795);
    assert_eq!(hotp_custom(from_hex("ff").unwrap().as_ref(), 23, 6, Sha1::new()), 330795);
    // test values from RFC 4226
    assert_eq!(hotp_raw(b"12345678901234567890", 0, 6), 755224);
    assert_eq!(hotp_raw(b"12345678901234567890", 1, 6), 287082);
    assert_eq!(hotp_raw(b"12345678901234567890", 2, 6), 359152);
    assert_eq!(hotp_raw(b"12345678901234567890", 3, 6), 969429);
    assert_eq!(hotp_raw(b"12345678901234567890", 4, 6), 338314);
    assert_eq!(hotp_raw(b"12345678901234567890", 5, 6), 254676);
    assert_eq!(hotp_raw(b"12345678901234567890", 6, 6), 287922);
    assert_eq!(hotp_raw(b"12345678901234567890", 7, 6), 162583);
    assert_eq!(hotp_raw(b"12345678901234567890", 8, 6), 399871);
    assert_eq!(hotp_raw(b"12345678901234567890", 9, 6), 520489);
    assert_eq!(hotp_custom(from_hex("ff").unwrap().as_ref(), 23, 6, Sha256::new()), 225210);
    assert_eq!(hotp_custom(from_hex("3f906a54263361fccf").unwrap().as_ref(), 10, 7, Sha1::new()), 7615146);
    assert_eq!(hotp_custom(from_hex("3f906a54263361fccf").unwrap().as_ref(), 10, 7, Sha256::new()), 6447746);
}

#[test]
fn test_totp() {
    use crypto::sha2::Sha256;
    use crypto::sha2::Sha512;
    assert_eq!(totp_custom(b"\xff", 6, 0, 1, 23, Sha1::new()), 330795);

    // test values from RFC 6238
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 59, Sha1::new()), 94287082);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 59, Sha256::new()), 46119246);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 59, Sha512::new()), 90693936);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111109, Sha1::new()), 07081804);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111109, Sha256::new()), 68084774);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111109, Sha512::new()), 25091201);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111111, Sha1::new()), 14050471);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111111, Sha256::new()), 67062674);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111111, Sha512::new()), 99943326);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1234567890, Sha1::new()), 89005924);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1234567890, Sha256::new()), 91819424);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1234567890, Sha512::new()), 93441116);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 2000000000, Sha1::new()), 69279037);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 2000000000, Sha256::new()), 90698825);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 2000000000, Sha512::new()), 38618901);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 20000000000, Sha1::new()), 65353130);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 20000000000, Sha256::new()), 77737706);
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 20000000000, Sha512::new()), 47863826);
}
