# rust-oath [![Build Status](https://travis-ci.org/vlad003/rust-oath.svg)](https://travis-ci.org/vlad003/rust-oath)


This library aims to provide implementations of HOTP, TOTP, and OCRA as
specified by the RFCs.

Implemented:

* HOTP ([RFC 4226](http://tools.ietf.org/html/rfc4226))
* TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238))

Planned:

* OCRA ([RFC 6287](https://tools.ietf.org/html/rfc6287))

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
