# rust-oath [![Build Status](https://travis-ci.org/vlad003/rust-oath.svg)](https://travis-ci.org/vlad003/rust-oath)


This library aims to provide implementations of HOTP, TOTP, and OCRA as
specified by the RFCs.

Implemented:

* HOTP ([RFC 4226](http://tools.ietf.org/html/rfc4226))
* TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238))

Planned:

* OCRA ([RFC 6287](https://tools.ietf.org/html/rfc6287))

**NOTE:** SHA2 doesn't work. Only SHA1 works. Why? I haven't been able to
figure that out. It might be an issue in the `rust-crypto` library, but I
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
