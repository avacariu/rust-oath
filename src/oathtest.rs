#![cfg(test)]
use super::*;

static NULL: &[u8] = &[];
static STANDARD_KEY_20: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30];
static STANDARD_KEY_32: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32];
static STANDARD_KEY_64: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                                    0x31, 0x32, 0x33, 0x34];
static PIN_1234_SHA1: &[u8] = &[0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a, 0xa5, 0xe4,
                                0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0x0d, 0x2c, 0x02, 0x20];
#[test]
fn sha1_pin_correct() {
    let mut sha: Sha1 = Sha1::new();
    sha.input_str("1234");

    let mut output = [0u8; 20];
    sha.result(&mut output);

    assert!(&PIN_1234_SHA1[..] == output);
}

#[test]
fn test_hotp() {
    let var_23_as_be_arr = [0, 0, 0, 0, 0, 0, 0, 23];
    let var_10_as_be_arr = [0, 0, 0, 0, 0, 0, 0, 10];

    assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);
    assert_eq!(hotp("ff", 23, 6).unwrap(), 330795);
    assert_eq!(hotp_custom(b"\xff", &var_23_as_be_arr, 6, Sha1::new()), 330795);
    assert_eq!(hotp_custom(from_hex("ff").unwrap().as_ref(), &var_23_as_be_arr, 6, Sha1::new()), 330795);
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
    //assert_eq!(hotp_custom(from_hex("ff").unwrap().as_ref(), 23, 6, Sha256::new()), 225210);
    assert_eq!(hotp_custom(from_hex("3f906a54263361fccf").unwrap().as_ref(), &var_10_as_be_arr, 7, Sha1::new()), 7615146);
    //assert_eq!(hotp_custom(from_hex("3f906a54263361fccf").unwrap().as_ref(), 10, 7, Sha256::new()), 6447746);
}

#[test]
fn test_totp() {
    assert_eq!(totp_custom(b"\xff", 6, 0, 1, 23, Sha1::new()), 330795);

    // test values from RFC 6238
    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 59, Sha1::new()), 94287082);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 59, Sha256::new()), 46119246);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 59, Sha512::new()), 90693936);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111109, Sha1::new()), 07081804);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111109, Sha256::new()), 68084774);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111109, Sha512::new()), 25091201);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111111, Sha1::new()), 14050471);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111111, Sha256::new()), 67062674);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1111111111, Sha512::new()), 99943326);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1234567890, Sha1::new()), 89005924);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1234567890, Sha256::new()), 91819424);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 1234567890, Sha512::new()), 93441116);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 2000000000, Sha1::new()), 69279037);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 2000000000, Sha256::new()), 90698825);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 2000000000, Sha512::new()), 38618901);

    assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 20000000000, Sha1::new()), 65353130);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 20000000000, Sha256::new()), 77737706);
    //assert_eq!(totp_custom(b"12345678901234567890", 8, 0, 30, 20000000000, Sha512::new()), 47863826);
}

#[test]
fn test_ocra_20byte_sha1() {
    let suite = "OCRA-1:HOTP-SHA1-6:QN08";

    // Test values from RFC 6287
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "00000000", NULL, NULL, 0), Ok(237653));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "11111111", NULL, NULL, 0), Ok(243178));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "22222222", NULL, NULL, 0), Ok(653583));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "33333333", NULL, NULL, 0), Ok(740991));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "44444444", NULL, NULL, 0), Ok(608993));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "55555555", NULL, NULL, 0), Ok(388898));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "66666666", NULL, NULL, 0), Ok(816933));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "77777777", NULL, NULL, 0), Ok(224598));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "88888888", NULL, NULL, 0), Ok(750600));
    assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "99999999", NULL, NULL, 0), Ok(294470));

    // Values, generated from original Java source
    let suite2 = "OCRA-1:HOTP-SHA1-6:QH07";
    assert_eq!(ocra(&suite2, &STANDARD_KEY_20, 0, "153158E", NULL, NULL, 0), Ok(347935));
    assert_eq!(ocra(&suite2, &STANDARD_KEY_20, 0, "ABC1DEF", NULL, NULL, 0), Ok(857750));

    let suite3 = "OCRA-1:HOTP-SHA1-6:QH08";
    assert_eq!(ocra(&suite3, &STANDARD_KEY_20, 0, "F153158E", NULL, NULL, 0), Ok(004133));
    assert_eq!(ocra(&suite3, &STANDARD_KEY_20, 0, "ABC10DEF", NULL, NULL, 0), Ok(277962));

    // My values. Could be wrong.
    let suite4 = "OCRA-1:HOTP-SHA1-6:QA31";
    assert_eq!(ocra(&suite4, &STANDARD_KEY_20, 0, "Thanks avacariu for a nice lib!", NULL, NULL, 0), Ok(044742));
    assert_eq!(ocra(&suite4, &STANDARD_KEY_20, 0, "Hope to see it in crates.io  :)", NULL, NULL, 0), Ok(516968));
}

#[test]
fn test_ocra_32byte_sha256() {
    let suite_c = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
    let suite   = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";

    // Test values from RFC 6287
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 0, "12345678", PIN_1234_SHA1, NULL, 0), Ok(65347737));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 1, "12345678", PIN_1234_SHA1, NULL, 0), Ok(86775851));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 2, "12345678", PIN_1234_SHA1, NULL, 0), Ok(78192410));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 3, "12345678", PIN_1234_SHA1, NULL, 0), Ok(71565254));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 4, "12345678", PIN_1234_SHA1, NULL, 0), Ok(10104329));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 5, "12345678", PIN_1234_SHA1, NULL, 0), Ok(65983500));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 6, "12345678", PIN_1234_SHA1, NULL, 0), Ok(70069104));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 7, "12345678", PIN_1234_SHA1, NULL, 0), Ok(91771096));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 8, "12345678", PIN_1234_SHA1, NULL, 0), Ok(75011558));
    assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 9, "12345678", PIN_1234_SHA1, NULL, 0), Ok(08522129));

    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "00000000", PIN_1234_SHA1, NULL, 0), Ok(83238735));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "11111111", PIN_1234_SHA1, NULL, 0), Ok(01501458));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "22222222", PIN_1234_SHA1, NULL, 0), Ok(17957585));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "33333333", PIN_1234_SHA1, NULL, 0), Ok(86776967));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "44444444", PIN_1234_SHA1, NULL, 0), Ok(86807031));
}

#[test]
fn test_ocra_64byte_sha512() {
    let suite = "OCRA-1:HOTP-SHA512-8:C-QN08";

    // Test values from RFC 6287
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "00000000", NULL, NULL, 0), Ok(07016083));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 1, "11111111", NULL, NULL, 0), Ok(63947962));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 2, "22222222", NULL, NULL, 0), Ok(70123924));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 3, "33333333", NULL, NULL, 0), Ok(25341727));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 4, "44444444", NULL, NULL, 0), Ok(33203315));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 5, "55555555", NULL, NULL, 0), Ok(34205738));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 6, "66666666", NULL, NULL, 0), Ok(44343969));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 7, "77777777", NULL, NULL, 0), Ok(51946085));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 8, "88888888", NULL, NULL, 0), Ok(20403879));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 9, "99999999", NULL, NULL, 0), Ok(31409299));

    // Pin must be ignored due to suite settings
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "00000000", PIN_1234_SHA1, NULL, 0), Ok(07016083));
}

#[test]
fn test_ocra_64byte_sha512_t() {
    let suite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
    // "132d0b6" from RFC with 1M step
    let t = 0x132d0b6 * 60;  // 1_206_446_760

    // Test values from RFC 6287
    // Counter must be ignored.
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 55, "00000000", NULL, NULL, t), Ok(95209754));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 62, "11111111", NULL, NULL, t), Ok(55907591));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 18, "22222222", NULL, NULL, t), Ok(22048402));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 26, "33333333", NULL, NULL, t), Ok(24218844));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 99, "44444444", NULL, NULL, t), Ok(36209546));
}

#[test]
fn test_ocra_32byte_sha256_mutual() {
    let server_suite = "OCRA-1:HOTP-SHA256-8:QA08";
    let client_suite = "OCRA-1:HOTP-SHA256-8:QA08";

    assert_eq!(ocra(&server_suite, &STANDARD_KEY_32, 0, "CLI22220SRV11110", NULL, NULL, 0), Ok(28247970));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_32, 0, "CLI22221SRV11111", NULL, NULL, 0), Ok(01984843));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_32, 0, "CLI22222SRV11112", NULL, NULL, 0), Ok(65387857));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_32, 0, "CLI22223SRV11113", NULL, NULL, 0), Ok(03351211));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_32, 0, "CLI22224SRV11114", NULL, NULL, 0), Ok(83412541));

    assert_eq!(ocra(&client_suite, &STANDARD_KEY_32, 0, "SRV11110CLI22220", NULL, NULL, 0), Ok(15510767));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_32, 0, "SRV11111CLI22221", NULL, NULL, 0), Ok(90175646));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_32, 0, "SRV11112CLI22222", NULL, NULL, 0), Ok(33777207));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_32, 0, "SRV11113CLI22223", NULL, NULL, 0), Ok(95285278));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_32, 0, "SRV11114CLI22224", NULL, NULL, 0), Ok(28934924));
}

#[test]
fn test_ocra_64byte_sha512_mutual() {
    let server_suite = "OCRA-1:HOTP-SHA512-8:QA08";
    let client_suite = "OCRA-1:HOTP-SHA512-8:QA08-PSHA1";

    assert_eq!(ocra(&server_suite, &STANDARD_KEY_64, 0, "CLI22220SRV11110", NULL, NULL, 0), Ok(79496648));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_64, 0, "CLI22221SRV11111", NULL, NULL, 0), Ok(76831980));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_64, 0, "CLI22222SRV11112", NULL, NULL, 0), Ok(12250499));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_64, 0, "CLI22223SRV11113", NULL, NULL, 0), Ok(90856481));
    assert_eq!(ocra(&server_suite, &STANDARD_KEY_64, 0, "CLI22224SRV11114", NULL, NULL, 0), Ok(12761449));

    assert_eq!(ocra(&client_suite, &STANDARD_KEY_64, 0, "SRV11110CLI22220", PIN_1234_SHA1, NULL, 0), Ok(18806276));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_64, 0, "SRV11111CLI22221", PIN_1234_SHA1, NULL, 0), Ok(70020315));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_64, 0, "SRV11112CLI22222", PIN_1234_SHA1, NULL, 0), Ok(01600026));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_64, 0, "SRV11113CLI22223", PIN_1234_SHA1, NULL, 0), Ok(18951020));
    assert_eq!(ocra(&client_suite, &STANDARD_KEY_64, 0, "SRV11114CLI22224", PIN_1234_SHA1, NULL, 0), Ok(32528969));
}

#[test]
fn test_ocra_32byte_sha256_signature() {
    let suite = "OCRA-1:HOTP-SHA256-8:QA08";

    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "SIG10000", NULL, NULL, 0), Ok(53095496));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "SIG11000", NULL, NULL, 0), Ok(04110475));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "SIG12000", NULL, NULL, 0), Ok(31331128));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "SIG13000", NULL, NULL, 0), Ok(76028668));
    assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "SIG14000", NULL, NULL, 0), Ok(46554205));
}

#[test]
fn test_ocra_64byte_sha512_signature_t() {
    let suite = "OCRA-1:HOTP-SHA512-8:QA10-T1M";
    let timestamp = 0x132d0b6 * 60;  // Timestamp from RFC with 1 minute coefficient

    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "SIG1000000", NULL, NULL, timestamp), Ok(77537423));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "SIG1100000", NULL, NULL, timestamp), Ok(31970405));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "SIG1200000", NULL, NULL, timestamp), Ok(10235557));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "SIG1300000", NULL, NULL, timestamp), Ok(95213541));
    assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "SIG1400000", NULL, NULL, timestamp), Ok(65360607));
}

#[test]
fn negative_tests_ocra() {
    assert_eq!(ocra_debug("OCRA-2:HOTP-SHA512-8:QA10-T1M", &STANDARD_KEY_64, 0, "SIG1000000", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Malformed suite string.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA512-8:QA10:MORE", &STANDARD_KEY_64, 0, "SIG1000000", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Malformed suite string.");
    assert_eq!(ocra_debug("OCRA-1:SOTP-SHA512-8:QA10-T1M", &STANDARD_KEY_32, 0, "Question#1", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Only HOTP crypto function is supported. You requested SOTP.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1024-8:QN08", &STANDARD_KEY_32, 0, "12345678", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Unknown hash type. Supported: SHA1/SHA256/SHA512. Requested: SHA1024.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-3:QN08", &STANDARD_KEY_32, 0, "12345678", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Number of returned digits should satisfy: 4 <= num <= 10. You requested 3.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-11:QN08", &STANDARD_KEY_32, 0, "12345678", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Number of returned digits should satisfy: 4 <= num <= 10. You requested 11.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QR08", &STANDARD_KEY_64, 0, "12345678", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "This question type is not supported! Use A/N/H, please. Can't parse question QR08.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN0F", &STANDARD_KEY_64, 0, "12345678", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Can't parse question length. Can't parse question QN0F.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN03", &STANDARD_KEY_64, 0, "123", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Make sure you request question length such that 4 <= question_length <= 64. Can't parse question QN03.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA256-6:QN65", &STANDARD_KEY_64, 0, "1234567890", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Make sure you request question length such that 4 <= question_length <= 64. Can't parse question QN65.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA256-8:QN08-PMD5", &STANDARD_KEY_32, 0, "11111111", PIN_1234_SHA1, NULL, 0).expect_err("Test failed!").as_str()
                          , "Unknown hashing algorithm. Can't parse hash PMD5.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA256-8:QN08-PSHA3", &STANDARD_KEY_32, 0, "11111111", PIN_1234_SHA1, NULL, 0).expect_err("Test failed!").as_str()
                          , "Unknown SHA hash mode. Can't parse hash PSHA3.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA256-8:QN08-PSHA256", &STANDARD_KEY_32, 0, "11111111", PIN_1234_SHA1, NULL, 0).expect_err("Test failed!").as_str()
                          , "Wrong hashed password length.");
    // Session info parameter can be "064", not just "64"
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN08-S64", &STANDARD_KEY_32, 0, "11111111", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Wrong session info length. Possible values: 064, 128, 256, 512. Wrong session info parameter S64.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN08-T1D", &STANDARD_KEY_32, 0, "11111111", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Can't parse timestamp. S/M/H time intervals are supported. Wrong timestamp parameter T1D.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN08-T0M", &STANDARD_KEY_64, 0, "11111111", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Wrong timestamp value. Wrong timestamp parameter T0M.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN08-T60M", &STANDARD_KEY_32, 0, "22222222", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Wrong timestamp value. Wrong timestamp parameter T60M.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA1-8:QN08-T49H", &STANDARD_KEY_32, 0, "99999999", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Time interval is too big. Use H <= 48. Wrong timestamp parameter T49H.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA512-8:QN08-WD40", &STANDARD_KEY_32, 0, "12345678", NULL, NULL, 0).expect_err("Test failed!").as_str()
                          , "Unknown parameter WD40.");
    assert_eq!(ocra_debug("OCRA-1:HOTP-SHA512-8:C-T2H", &STANDARD_KEY_32, 0, "12345678", NULL, NULL, 456).expect_err("Test failed!").as_str()
                          , "No question parameter specified or question length is 0.");
}