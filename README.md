# oath2
[![Build Status](https://travis-ci.org/crypto-universe/oath2.svg?branch=master)](https://travis-ci.org/crypto-universe/oath2)
[![oath2 on crates.io](https://img.shields.io/crates/v/oath2.svg)](https://crates.io/crates/oath2)
[![Documentation](https://docs.rs/oath2/badge.svg)](https://docs.rs/oath2/)
[![MIT license](https://img.shields.io/dub/l/vibe-d.svg)](https://opensource.org/licenses/MIT)


This library aims to provide implementations of HOTP, TOTP, and OCRA as
specified by the RFCs. oath2 is a successor of [oath](https://github.com/avacariu/rust-oath)
library. I had to fork it, because avacariu doesn't react on PRs.

Implemented:

* HOTP ([RFC 4226](http://tools.ietf.org/html/rfc4226))
* TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238))
* OCRA ([RFC 6287](https://tools.ietf.org/html/rfc6287))

**WARNING** While [ieee754 is broken](https://github.com/rust-lang/rust/issues/41793),
[RAMP](https://crates.io/crates/ramp) fails to compile.
OCRA numeric question mode can't use long Int, it is forced to use u64 instead.
This data type leads us to question length limitation: 19 symbols. Number must fit u64.
For default challenge format (N08) it is more that enough.

## Examples

### HOTP

    extern crate oath2;

    use oath2::hotp;

    fn main () {
        assert_eq!(hotp("ff", 23, 6).unwrap(), 330795);
    }

### TOTP

All the times below are in seconds.

    extern crate oath2;

    use oath2::{totp_raw_now, HashType};

    fn main () {
        // Return value differs every 30 seconds.
        totp_raw_now(b"12345678901234567890", 6, 0, 30, &HashType::SHA1);
    }

### OCRA

    extern crate oath2;

    use oath2::ocra;

    let NULL: &[u8] = &[];
    let STANDARD_KEY_20: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
    let STANDARD_KEY_32 = "12345678901234567890123456789012".as_bytes();
    let STANDARD_KEY_64 = "1234567890123456789012345678901234567890123456789012345678901234".as_bytes();
    let PIN_1234_SHA1: &[u8] = &[0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a, 0xa5, 0xe4,
                                 0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0x0d, 0x2c, 0x02, 0x20];

    let suite = "OCRA-1:HOTP-SHA1-6:QN08";
    let result = ocra(&suite, &STANDARD_KEY_20, 0, "00000000", NULL, NULL, 0)
    assert_eq!(result, Ok(237653));

    // Attention! PIN must be already hashed!
    let suite_c = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
    let result_c = ocra(&suite_c, &STANDARD_KEY_32, 8, "12345678", PIN_1234_SHA1, NULL, 0);
    assert_eq!(result_c, Ok(75011558));

    let suite_t = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
    let t = 1_206_446_760; // UTC time in seconds
    let result_t = ocra(&suite, &STANDARD_KEY_64, 18, "22222222", NULL, NULL, t);
    assert_eq!(result_t, Ok(22048402));

### Google Authenticator

Keys provided by Google are encoded using base32. You'll need to convert them
before passing them to any of the functions in this crate.

A simple way to do this is using the [base32](https://crates.io/crates/base32/)
crate.

    // assuming AAAAAAAAAAAAAAAA is your key
    base32::decode(base32::Alphabet::RFC4648 {padding: false}, "AAAAAAAAAAAAAAAA").unwrap().as_ref()

And pass the result of that as the key parameter to the HOTP and TOTP
functions.

### Misc

If you don't want to use other crates for hex conversion, this library provides a
convenient function `from_hex()`. This helps with the functions that expect byte
arrays.

    let seed = oath::from_hex("ff").unwrap();
    totp_raw(seed.as_slice(), 6, 0, 30);

## Licensing

This library is licensed under the MIT license. If you're a potential user, or
a current user, and this license causes an issue for you, I'm willing to
consider multi-licensing it.
