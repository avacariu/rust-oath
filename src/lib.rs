extern crate crypto;
extern crate rustc_serialize;
extern crate time;
extern crate ramp;

use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use rustc_serialize::hex::FromHex;
use rustc_serialize::hex::ToHex;
use std::io::Write as Write_io;
use std::fmt::Write as Write_fmt;
use ramp::Int;

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

fn dynamic_truncation(hs: &[u8]) -> u64 {
    let offset_bits = (hs[hs.len()-1] & 0xf) as usize;
    let p = u64_from_be_bytes_4(hs, offset_bits);

    p & 0x7fffffff
}

pub fn hotp_custom<D: Digest>(key: &[u8], message: &[u8], digits: u32,
                              hash: D) -> u64 {
    let mut hmac = Hmac::new(hash, key);
    hmac.input(message);
    let result = hmac.result();
    let hs = result.code();

    dynamic_truncation(hs) % 10_u64.pow(digits)
}

pub fn hotp_raw(key: &[u8], counter: u64, digits: u32) -> u64 {
    let hash = Sha1::new();
    let message = counter.to_be();
    let msg_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&message as *const u64 as *const u8, 8) };
    hotp_custom(key, msg_ptr, digits, hash)
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
    let message = counter.to_be();
    let msg_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&message as *const u64 as *const u8, 8) };
    hotp_custom(key, msg_ptr, digits, hash)
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

pub fn ocra<'a>(suite: &str, key: &[u8], counter: u64, question: &str,
        password: &[u8], _session_info: &[u8], _timestamp: &[u8]) -> Result<u64, &'a str> {
    let parsed_suite: Vec<&str> = suite.split(':').collect();
    if (parsed_suite.len() != 3) || (parsed_suite[0].to_uppercase() != "OCRA-1") {
        return Err("Malformed suite string.");
    }

    let crypto_function: Vec<&str> = parsed_suite[1].split('-').collect();
    if crypto_function[0].to_uppercase() != "HOTP" {
        return Err("Only HOTP crypto function is supported.");
    }

    let hotp_sha_type: SType = match crypto_function[1].to_uppercase().as_str() {
        "SHA1" => SType::SHA1,
        "SHA256" => SType::SHA256,
        "SHA512" => SType::SHA512,
        _ => return Err("Unknown hash type.")
    };

    let num_of_digits = if crypto_function.len() == 3 {
        let temp_num = crypto_function[2].parse().unwrap_or(0);
        if temp_num > 10 || temp_num < 4 {
            return Err("Number of returned digits should satisfy: 4 <= num <= 10.");
        }
        temp_num
    } else {
        0
    };

    let data_input: Vec<&str> = parsed_suite[2].split('-').collect();
    // Counters
    let     question_len:   usize = 128;
    let mut counter_len:    usize = 0;
    let mut hashed_pin_len: usize = 0;

    let mut parsed_question_type: (QType, usize) = (QType::N, 0);
    let mut parsed_pin_sha_type: (SType, usize);

    for p in data_input {
        let setting: &[u8] = p.as_bytes();
        match setting[0] {
            b'q' | b'Q' => {
                match ocra_parse_question(p) {
                    Ok(expr) => {
                        parsed_question_type = expr;
                        if question.len() != parsed_question_type.1 {
                            return Err("Claimed and real question lengths are different.");
                        }
                    },
                    Err(_) => return Err("Can't parse question."),
                };
            },
            b'c' | b'C' => counter_len = 8,
            b'p' | b'P' => {
                match parse_pin_sha_type(p) {
                    Ok(expr) => {
                        parsed_pin_sha_type = expr;
                        hashed_pin_len = parsed_pin_sha_type.1;
                        if password.len() != hashed_pin_len {
                            return Err("Wrong hashed password length.");
                        }
                    },
                    Err(_) => return Err("Can't parse hash."),
                };
            },
            _ => return Err("Unknown parameter."),
        }
    }

    let full_message_len = suite.len() + 1 + counter_len + question_len + hashed_pin_len;
    let message_len_for_resizing = suite.len() + 1 + counter_len + question_len;

    let mut message: Vec<u8> = Vec::with_capacity(full_message_len);
    message.extend_from_slice(suite.as_bytes());
    message.push(0u8);    //Delimiter. Mandatory!
    if counter_len > 0 {
        let counter_be = counter.to_be();
        let msg_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&counter_be as *const u64 as *const u8, 8) };
        message.extend_from_slice(msg_ptr);
    }
    if parsed_question_type.1 != 0 {
        let push_result = push_correct_question(&mut message, parsed_question_type, question);
        match push_result {
            Ok(_) => message.resize(message_len_for_resizing, 0),
            Err(err_str) => return Err(err_str),
        }
    } else {
        return Err("No question parameter specified or question length is 0.");
    }
    if hashed_pin_len > 0 {
        message.extend_from_slice(password);
    }

    let result: u64 = match hotp_sha_type {
        SType::SHA1 => hotp_custom(key, message.as_slice(), num_of_digits, Sha1::new()),
        SType::SHA256 => hotp_custom(key, message.as_slice(), num_of_digits, Sha256::new()),
        SType::SHA512 => hotp_custom(key, message.as_slice(), num_of_digits, Sha512::new()),
    };

    Ok(result)
}

enum SType {SHA1, SHA256, SHA512}
fn parse_pin_sha_type(psha: &str) -> Result<(SType, usize), &str> {
    let psha_local: String = psha.to_uppercase();
    if psha_local.starts_with("PSHA") {
        let (_, num) = psha_local.split_at(4);
        match num {
            "1" => Ok((SType::SHA1, 20)),
            "256" => Ok((SType::SHA256, 32)),
            "512" => Ok((SType::SHA512, 64)),
            _ => Err("Unknown SHA hash modification"),
        }
    } else {
        Err("Unknown hashing algorithm")
    }
}

fn push_correct_question<'a>(message: &mut Vec<u8>, q_info: (QType, usize), question: &str) -> Result<(), &'a str> {
    let (q_type, q_length) = q_info;
    match q_type {
        QType::A => {
            let hex_representation: String = question.as_bytes().to_hex();
            let mut hex_encoded: Vec<u8> = hex_representation.from_hex().unwrap();
            message.append(hex_encoded.by_ref());
        },
        QType::N => {
            let q_as_int: Int = Int::from_str_radix(question, 10).expect("Can't parse your numeric question.");
            let sign = q_as_int.sign();
            if sign == -1 {
                return Err("Question number can't be negative!");
            }
            //Do nothing if sign == 0;
            if sign == 1 {
                // Let's make some calculations to prevent extra heap allocations.
                // from_hex expects string to be even, but ramp's to_str_radix
                // can return string with odd length
                // bit_length() = floor(log2(abs(self)))+1
                let bit_len: u32 = q_as_int.bit_length();
                let num_of_chars = if bit_len % 4 != 0 {
                    bit_len / 4 + 1
                } else {
                    bit_len / 4
                };
                let mut q_as_hex: String = String::with_capacity(num_of_chars as usize);
                let write_result = write!(&mut q_as_hex, "{:X}", q_as_int);
                match write_result {
                    Ok(_) => {
                        // Now tricky part! If length is odd, number must be padded with 0
                        // on the right. Numeric value will change!
                        // Padding on the left side (to keep number correct) will produce
                        // wrong result!
                        if num_of_chars % 2 == 1 {
                            q_as_hex.push('0');
                        }
                        message.append(from_hex(q_as_hex.as_str()).unwrap().by_ref());
                    },
                    Err(_) => return Err("Unexpected error. Can't write to buffer."),
                }

            }
        },
        QType::H => {
            if q_length % 2 == 0 {
                message.append(from_hex(question).unwrap().by_ref());
            } else {
                let mut question_owned = String::with_capacity(q_length + 1);
                question_owned.push_str(question);
                question_owned.push('0');
                message.append(from_hex(question_owned.as_str()).unwrap().by_ref());
            }
        },
    };

    Ok(())
}

enum QType {A, N, H}
fn ocra_parse_question(question: &str) -> Result<(QType, usize), &str> {
    assert_eq!(question.len(), 4);
    let (type_str, len_str) = question.split_at(2);

    let data: &[u8] = type_str.as_bytes();
    assert!(data[0] == b'Q' || data[0] == b'q');
    let q_type_result: Result<QType, &str> = match data[1] {
        b'a' | b'A' => Ok(QType::A),
        b'n' | b'N' => Ok(QType::N),
        b'h' | b'H' => Ok(QType::H),
        _           => Err("This question type is not supported! Use A/N/H, please."),
    };

    if q_type_result.is_err() {
        return Err(q_type_result.err().unwrap());
    }

    let q_len_result = len_str.parse::<usize>();
    if q_len_result.is_err() {
        return Err("Can't parse question length.");
    }

    let q_len = q_len_result.unwrap();
    if q_len < 4 && q_len > 64 {
        return Err("Make sure you request question length such that 4 <= question_length <= 64.");
    }

    Ok((q_type_result.unwrap(), q_len))
}

#[test]
fn test_hotp() {
    //use crypto::sha2::Sha256;

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
    //use crypto::sha2::Sha256;
    //use crypto::sha2::Sha512;
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

#[cfg(test)]
mod ocra_tests {
    use ocra;

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
        use crypto::sha1::Sha1;
        use crypto::digest::Digest;

        let mut sha: Sha1 = Sha1::new();
        sha.input_str("1234");

        let mut output = [0u8; 20];
        sha.result(&mut output);

        assert!(&PIN_1234_SHA1[..] == output);
    }

    #[test]
    fn test_ocra_20byte_sha1() {
        let suite = "OCRA-1:HOTP-SHA1-6:QN08";

        // Test values from RFC 6287
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "00000000", NULL, NULL, NULL), Ok(237653));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "11111111", NULL, NULL, NULL), Ok(243178));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "22222222", NULL, NULL, NULL), Ok(653583));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "33333333", NULL, NULL, NULL), Ok(740991));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "44444444", NULL, NULL, NULL), Ok(608993));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "55555555", NULL, NULL, NULL), Ok(388898));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "66666666", NULL, NULL, NULL), Ok(816933));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "77777777", NULL, NULL, NULL), Ok(224598));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "88888888", NULL, NULL, NULL), Ok(750600));
        assert_eq!(ocra(&suite, &STANDARD_KEY_20, 0, "99999999", NULL, NULL, NULL), Ok(294470));

        // Values, generated from original Java source
        let suite2 = "OCRA-1:HOTP-SHA1-6:QH07";
        assert_eq!(ocra(&suite2, &STANDARD_KEY_20, 0, "153158E", NULL, NULL, NULL), Ok(347935));
        assert_eq!(ocra(&suite2, &STANDARD_KEY_20, 0, "ABC1DEF", NULL, NULL, NULL), Ok(857750));

        let suite3 = "OCRA-1:HOTP-SHA1-6:QH08";
        assert_eq!(ocra(&suite3, &STANDARD_KEY_20, 0, "F153158E", NULL, NULL, NULL), Ok(004133));
        assert_eq!(ocra(&suite3, &STANDARD_KEY_20, 0, "ABC10DEF", NULL, NULL, NULL), Ok(277962));

        // My values. Could be wrong.
        let suite4 = "OCRA-1:HOTP-SHA1-6:QA31";
        assert_eq!(ocra(&suite4, &STANDARD_KEY_20, 0, "Thanks avacariu for a nice lib!", NULL, NULL, NULL), Ok(044742));
        assert_eq!(ocra(&suite4, &STANDARD_KEY_20, 0, "Hope to see it in crates.io  :)", NULL, NULL, NULL), Ok(516968));
    }

    #[test]
    fn test_ocra_32byte_sha256() {
        let suite_c = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
        let suite   = "OCRA-1:HOTP-SHA256-8:QN08-PSHA1";

        // Test values from RFC 6287
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 0, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(65347737));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 1, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(86775851));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 2, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(78192410));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 3, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(71565254));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 4, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(10104329));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 5, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(65983500));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 6, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(70069104));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 7, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(91771096));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 8, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(75011558));
        assert_eq!(ocra(&suite_c, &STANDARD_KEY_32, 9, "12345678", PIN_1234_SHA1, NULL, NULL), Ok(08522129));

        assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "00000000", PIN_1234_SHA1, NULL, NULL), Ok(83238735));
        assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "11111111", PIN_1234_SHA1, NULL, NULL), Ok(01501458));
        assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "22222222", PIN_1234_SHA1, NULL, NULL), Ok(17957585));
        assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "33333333", PIN_1234_SHA1, NULL, NULL), Ok(86776967));
        assert_eq!(ocra(&suite, &STANDARD_KEY_32, 0, "44444444", PIN_1234_SHA1, NULL, NULL), Ok(86807031));
    }

    #[test]
    fn test_ocra_64byte_sha512() {
        let suite = "OCRA-1:HOTP-SHA512-8:C-QN08";

        // Test values from RFC 6287
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "00000000", NULL, NULL, NULL), Ok(07016083));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 1, "11111111", NULL, NULL, NULL), Ok(63947962));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 2, "22222222", NULL, NULL, NULL), Ok(70123924));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 3, "33333333", NULL, NULL, NULL), Ok(25341727));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 4, "44444444", NULL, NULL, NULL), Ok(33203315));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 5, "55555555", NULL, NULL, NULL), Ok(34205738));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 6, "66666666", NULL, NULL, NULL), Ok(44343969));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 7, "77777777", NULL, NULL, NULL), Ok(51946085));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 8, "88888888", NULL, NULL, NULL), Ok(20403879));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 9, "99999999", NULL, NULL, NULL), Ok(31409299));

        // Pin must be ignored due to suite settings
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 0, "00000000", PIN_1234_SHA1, NULL, NULL), Ok(07016083));
    }

    #[test]
    #[ignore]   // Not implemented
    fn test_ocra_64byte_sha512_t() {
        let suite = "OCRA-1:HOTP-SHA512-8:QN08-T1M";
        let t = &[0x01, 0x32, 0xd0, 0xb6];

        // Test values from RFC 6287
        // Counter must be ignored.
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 55, "00000000", NULL, NULL, t), Ok(95209754));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 62, "11111111", NULL, NULL, t), Ok(55907591));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 18, "22222222", NULL, NULL, t), Ok(22048402));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 26, "33333333", NULL, NULL, t), Ok(24218844));
        assert_eq!(ocra(&suite, &STANDARD_KEY_64, 99, "44444444", NULL, NULL, t), Ok(36209546));
    }
}