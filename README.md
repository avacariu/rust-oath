# rust-oath [![Build Status](https://travis-ci.org/vlad003/rust-oath.svg)](https://travis-ci.org/vlad003/rust-oath)


This library aims to provide implementations of HOTP, TOTP, and OCRA as
specified by the RFCs.

Implemented:

* HOTP ([RFC 4226](http://tools.ietf.org/html/rfc4226))
* TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238))

Ongoing:

* OCRA ([RFC 6287](https://tools.ietf.org/html/rfc6287))

**NOTE:** SHA2 doesn't work for TOTP and HOTP. Only SHA1 works. Why? I haven't been
able to figure that out. It might be an issue in the `rust-crypto` library, but I
haven't been able to spot it. Digests are used interchangeably in my code, same
as in the `rust-crypto` HMAC code, so I don't know what's going on.

**PRs are more than welcome!** I'm not using Rust much these days, so I don't
notice if anything in this code breaks. If you send me a PR, I'll do my best to
merge it quickly.

## Examples

### HOTP

    // htop(key, counter, digits)
    // hotp_raw takes bytes as the key
    assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);
    // hotp takes a hex string as the key
    assert_eq!(hotp("ff", 23, 6), 330795);

    hotp_custom(b"\xff", 23, 6, Sha1::new());

### TOTP

All the times below are in seconds.

    // totp(key, digits, epoch, time_step)
    totp("ff", 6, 0, 30); // defaults for most TOTP implementations
    totp_raw(b"\xff", 6, 0, 30);
    // totp_custom(key, digits, epoch, time_step, current_time, hash)
    totp_custom(b"\xff", 6, 0, 30, 255, Sha1::new());

### OCRA

    NULL: &[u8] = &[];
    STANDARD_KEY_20: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                               0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
    STANDARD_KEY_32: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                               0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                               0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                               0x31, 0x32];
    PIN_1234_SHA1: &[u8] = &[0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a, 0xa5, 0xe4,
                             0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0x0d, 0x2c, 0x02, 0x20];

    let suite = "OCRA-1:HOTP-SHA1-6:QN08";
    let result = ocra(&suite, &STANDARD_KEY_20, 0, "00000000", NULL, NULL, NULL)
    assert_eq!(result, Ok(237653));
    // Attention! PIN must be already hashed!
    let suite_c = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
    let result_c = ocra(&suite_c, &STANDARD_KEY_32, 8, "12345678", PIN_1234_SHA1, NULL, NULL);
    assert_eq!(result_c, Ok(75011558));

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

If you don't want to use `rustc-serialize` directly, this library provides a
wrapper around `from_hex()`. This helps with the functions that expect byte
arrays.

    let seed = oath::from_hex("ff").unwrap();
    totp_raw(seed.as_slice(), 6, 0, 30);

## Licensing

This library is licensed under the MIT license. If you're a potential user, or
a current user, and this license causes an issue for you, I'm willing to
consider multi-licensing it.
