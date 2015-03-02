# rust-oath [![Build Status](https://travis-ci.org/vlad003/rust-oath.svg)](https://travis-ci.org/vlad003/rust-oath)


This library aims to provide implementations of HOTP, TOTP, and OCRA as
specified by the RFCs.

Functioning:

* HOTP ([RFC 4226](http://tools.ietf.org/html/rfc4226))

Planned:

* TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238))
* OCRA ([RFC 6287](https://tools.ietf.org/html/rfc6287))

## Examples

    // htop(key, counter, digits)
    // hotp_raw takes bytes as the key
    assert_eq!(hotp_raw(b"\xff", 23, 6), 330795)
    // hotp takes a hex string as the key
    assert_eq!(hotp("ff", 23, 6), 330795)
