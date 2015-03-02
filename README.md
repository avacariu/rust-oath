# rust-oath [![Build Status](https://travis-ci.org/vlad003/rust-oath.svg)](https://travis-ci.org/vlad003/rust-oath)


This library aims to provide implementations of HOTP, TOTP, and OCRA as
specified by the RFCs.

Functioning:

* HOTP ([RFC 4226](http://tools.ietf.org/html/rfc4226))

Planned:

* TOTP ([RFC 6238](http://tools.ietf.org/html/rfc6238))
* OCRA ([RFC 6287](https://tools.ietf.org/html/rfc6287))

## Examples

The `hotp` function requires the key to be represented as a byte string. It
might be nice for it accept a hex or base32 string instead, but I wanted to
limit the number of dependencies.

    // htop(key, counter, digits)
    assert_eq!(hotp(b"\xff", 23, 6), 330795)
