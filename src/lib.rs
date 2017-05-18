//! rust-oath is a rust implementation of three one-time password generators:
//! [HOTP](https://www.ietf.org/rfc/rfc4226.txt),
//! [TOTP](https://www.ietf.org/rfc/rfc6238.txt),
//! [OCRA](https://www.ietf.org/rfc/rfc6287.txt)

#![warn(missing_docs)]

extern crate crypto;
extern crate rustc_serialize;
extern crate time;
//extern crate ramp;

use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::digest::Digest;
use rustc_serialize::hex::FromHex;
use rustc_serialize::hex::ToHex;
use std::io::Write as Write_io;
//use std::fmt::Write as Write_fmt;
//use ramp::Int;

mod oathtest;

/// HashType enum represents possible hashing modes.
pub enum HashType {
    /// Sha1
    SHA1,
    /// Sha2 256 bit mode
    SHA256,
    /// Sha2 512 bit mode
    SHA512
}

/// This library provides a wrapper around `rustc_serialize::hex::from_hex()`.
/// This helps with the functions that expect byte arrays.
///
/// # Examples
///
/// ```
/// extern crate oath;
///
/// use oath::{totp_raw_now, HashType};
///
/// fn main () {
///     let seed = oath::from_hex("ff").unwrap();
///     totp_raw_now(seed.as_slice(), 6, 0, 30, HashType::SHA1);
/// }
/// ```
pub fn from_hex(data: &str) -> Result<Vec<u8>, &str> {
    match data.from_hex() {
        Ok(d) => Ok(d),
        Err(_) => Err("Unable to decode hex")
    }
}

#[inline]
fn u64_from_be_bytes_4(bytes: &[u8], start: usize) -> u64 {
    let mut val = 0u64;

    val += (bytes[start]   as u64) << ((3 * 8) as u64);
    val += (bytes[start+1] as u64) << ((2 * 8) as u64);
    val += (bytes[start+2] as u64) << ((1 * 8) as u64);
    val += (bytes[start+3] as u64) << ((0 * 8) as u64);

    val
}

#[inline]
fn dynamic_truncation(hs: &[u8]) -> u64 {
    let offset_bits = (hs[hs.len()-1] & 0xf) as usize;
    let p = u64_from_be_bytes_4(hs, offset_bits);

    p & 0x7fffffff
}

fn hmac_and_truncate<D: Digest>(key: &[u8], message: &[u8], digits: u32,
                              hash: D) -> u64 {
    let mut hmac = Hmac::new(hash, key);
    hmac.input(message);
    let result = hmac.result();
    let hs = result.code();

    dynamic_truncation(hs) % 10_u64.pow(digits)
}

/// Computes an one-time password using HOTP algorithm.
/// Same as [`hotp`](fn.hotp.html), but expects key to be a `&[u8]`.
///
/// `key` is a slice, that represents the shared secret;
///
/// `counter` is a counter. Due to [RFC4226](https://www.ietf.org/rfc/rfc4226.txt) it MUST be synchronized between the
/// HOTP generator (client) and the HOTP validator (server);
///
/// `digits` - number of digits in output (usually 6 or 8);
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::hotp_raw;
///
/// fn main () {
///     assert_eq!(hotp_raw(b"\xff", 23, 6), 330795);
/// }
/// ```
pub fn hotp_raw(key: &[u8], counter: u64, digits: u32) -> u64 {
    let hash = Sha1::new();
    let message = counter.to_be();
    let msg_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&message as *const u64 as *const u8, 8) };
    hmac_and_truncate(key, msg_ptr, digits, hash)
}

/// Hi-level function, that computes an one-time password using HOTP algorithm.
/// Same as [`hotp_raw`](fn.hotp_raw.html), but expects key to be a `&str` instead.
///
/// `key` is a string slice, that represents the shared secret;
///
/// `counter` is a counter. Due to [RFC4226](https://www.ietf.org/rfc/rfc4226.txt) it MUST be synchronized between the
/// HOTP generator (client) and the HOTP validator (server);
///
/// `digits` - number of digits in output (usually 6 or 8);
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::hotp;
///
/// fn main () {
///     assert_eq!(hotp("ff", 23, 6).unwrap(), 330795);
/// }
/// ```
pub fn hotp(key: &str, counter: u64, digits: u32) -> Result<u64, &str> {
    match key.from_hex() {
        Ok(bytes) => Ok(hotp_raw(bytes.as_ref(), counter, digits)),
        Err(_) => Err("Unable to parse hex.")
    }
}

/// Low-level function, that computes an one-time password using TOTP algorithm.
///
/// `key` is a slice, that represents the shared secret;
///
/// `digits` - number of digits in output (usually 6 or 8);
///
/// `epoch` - initial counter time T0 (default value is 0);
///
/// `time_step` - time step in seconds (default value is 30);
///
/// `current_time` - current Unix time (in seconds);
///
/// `hash` is a hashing algorithm. Can be Sha1, Sha256, Sha512;
///
/// # Example
///
/// ```
/// extern crate crypto;
/// extern crate oath;
///
/// use crypto::sha1::Sha1;
/// use oath::totp_custom;
///
/// fn main () {
///     assert_eq!(totp_custom(b"\xff", 6, 0, 1, 23, Sha1::new()), 330795);
/// }
/// ```
pub fn totp_custom<D: Digest>(key: &[u8], digits: u32, epoch: u64,
                              time_step: u64, current_time: u64,
                              hash: D) -> u64 {
    let counter: u64 = (current_time - epoch) / time_step;
    let message = counter.to_be();
    let msg_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&message as *const u64 as *const u8, 8) };
    hmac_and_truncate(key, msg_ptr, digits, hash)
}

/// Computes an one-time password using TOTP algorithm for arbitrary timestamp.
/// Same as [`totp_custom_time`](fn.totp_custom_time.html), but expects key to be a `&[u8]`.
///
/// `key` is a slice, that represents the shared secret;
///
/// `digits` - number of digits in output (usually 6 or 8);
///
/// `epoch` - initial counter time T0 (default value is 0);
///
/// `time_step` - time step in seconds (default value is 30);
///
/// `timestamp` - moment of time to be computed (in seconds);
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::{totp_raw_custom_time, HashType};
///
/// fn main () {
///     totp_raw_custom_time(b"12345678901234567890", 6, 0, 30, 26*365*24*60*60, HashType::SHA1);
/// }
/// ```
pub fn totp_raw_custom_time(key: &[u8], digits: u32, epoch: u64, time_step: u64,
                            timestamp: u64, hash: HashType) -> u64 {
    match hash {
        HashType::SHA1   => totp_custom(key, digits, epoch, time_step, timestamp, Sha1::new()),
        HashType::SHA256 => totp_custom(key, digits, epoch, time_step, timestamp, Sha256::new()),
        HashType::SHA512 => totp_custom(key, digits, epoch, time_step, timestamp, Sha512::new()),
    }
}

/// Computes an one-time password for this moment using TOTP algorithm.
/// Same as [`totp_now`](fn.totp_now.html), but expects key to be a `&[u8]`.
///
/// `key` is a slice, that represents the shared secret;
///
/// `digits` - number of digits in output (usually 6 or 8);
///
/// `epoch` - initial counter time T0 (default value is 0);
///
/// `time_step` - time step in seconds (default value is 30);
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::{totp_raw_now, HashType};
///
/// fn main () {
///     // Return value differs every 30 seconds.
///     totp_raw_now(b"12345678901234567890", 6, 0, 30, HashType::SHA1);
/// }
/// ```
pub fn totp_raw_now(key: &[u8], digits: u32, epoch: u64, time_step: u64, hash: HashType) -> u64 {
    let current_time: u64 = time::get_time().sec as u64;
    totp_raw_custom_time(key, digits, epoch, time_step, current_time, hash)
}

/// Computes an one-time password using TOTP algorithm for arbitrary timestamp.
/// Same as [`totp_raw_custom_time`](fn.totp_raw_custom_time.html), but expects key to be a `&str` and returns Result.
///
/// `key` is a string slice, that represents the shared secret;
///
/// `digits` - number of digits in output;
///
/// `epoch` - initial counter time T0 (default value is 0);
///
/// `time_step` - time step in seconds (default value is 30);
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::{totp_custom_time, HashType};
///
/// fn main () {
///     // Returns TOTP result for 436437456 second after 1 Jan 1970
///     totp_custom_time("0F35", 6, 0, 30, 436437456, HashType::SHA512);
/// }
/// ```
pub fn totp_custom_time(key: &str, digits: u32, epoch: u64,
                        time_step: u64, timestamp: u64, hash: HashType) -> Result<u64, &str> {
    match key.from_hex() {
        Ok(bytes) => Ok(totp_raw_custom_time(bytes.as_ref(), digits, epoch, time_step, timestamp, hash)),
        Err(_) => Err("Unable to parse hex.")
    }
}

/// Computes an one-time password for current moment of time using TOTP algorithm.
/// Same as [`totp_raw_now`](fn.totp_raw_now.html), but expects key to be a `&str` and returns Result.
///
/// `key` is a string slice, that represents the shared secret;
///
/// `digits` - number of digits in output;
///
/// `epoch` - initial counter time T0 (default value is 0)
///
/// `time_step` - time step in seconds (default value is 30)
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::{totp_now, HashType};
///
/// fn main () {
///     // Return value differs every 30 seconds.
///     totp_now("0F35", 6, 0, 30, HashType::SHA512);
/// }
/// ```
pub fn totp_now(key: &str, digits: u32, epoch: u64,
            time_step: u64, hash: HashType) -> Result<u64, &str> {
    match key.from_hex() {
        Ok(bytes) => Ok(totp_raw_now(bytes.as_ref(), digits, epoch, time_step, hash)),
        Err(_) => Err("Unable to parse hex.")
    }
}

/// ocra is a wrapper over [`ocra_debug`](fn.ocra_debug.html) function. Use this function in production code!
/// ocra function doesn't leak any info about internal errors, because
/// such internal info could be a starting point for hackers.
pub fn ocra(suite: &str, key: &[u8], counter: u64, question: &str,
        password: &[u8], session_info: &[u8], num_of_time_steps: u64) -> Result<u64, ()> {
    ocra_debug(suite, key, counter, question, password, session_info, num_of_time_steps).or(Err(()))
}

/// ocra_debug is an [OCRA](https://tools.ietf.org/html/rfc6287) implementation with
/// detailed errors descriptions. Use it for debugging purpose only!
/// For production code use [`ocra`](fn.ocra.html) function.
///
/// `suite` is a value representing the suite of operations to compute an OCRA response;
///
/// `key` is a secret, previously shared between client and server;
///
/// `counter` optional synchronized between the client and the server u64 counter;
///
/// `question` mandatory challenge question(s) generated by the parties;
///
/// `password` optional ALREADY HASHED value of PIN/password that is known to all parties
/// during the execution of the algorithm;
///
/// `session_info` optional information about the current session;
///
/// `num_of_time_steps` optional number of time steps since midnight UTC of January 1, 1970;
/// step size is predefined in the suite;
///
/// # Example
///
/// ```
/// extern crate oath;
///
/// use oath::ocra;
///
/// fn main () {
///     let suite_c = "OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1";
///     let STANDARD_KEY_32 = b"12345678901234567890123456789012";
///     let PIN_1234_SHA1 = &[0x71, 0x10, 0xed, 0xa4, 0xd0, 0x9e, 0x06, 0x2a, 0xa5, 0xe4,
///                           0xa3, 0x90, 0xb0, 0xa5, 0x72, 0xac, 0x0d, 0x2c, 0x02, 0x20];
///     assert_eq!(ocra(&suite_c, STANDARD_KEY_32, 6, "12345678", PIN_1234_SHA1, &[], 0), Ok(70069104));
/// }
/// ```
pub fn ocra_debug(suite: &str, key: &[u8], counter: u64, question: &str,
        password: &[u8], session_info: &[u8], num_of_time_steps: u64) -> Result<u64, String> {
    let parsed_suite: Vec<&str> = suite.split(':').collect();
    if (parsed_suite.len() != 3) || (parsed_suite[0].to_uppercase() != "OCRA-1") {
        return Err("Malformed suite string.".to_string());
    }

    let crypto_function: Vec<&str> = parsed_suite[1].split('-').collect();
    if crypto_function[0].to_uppercase() != "HOTP" {
        return Err("Only HOTP crypto function is supported. You requested ".to_string() + crypto_function[0] + ".");
    }

    let hotp_sha_type: HashType = match crypto_function[1].to_uppercase().as_str() {
        "SHA1" => HashType::SHA1,
        "SHA256" => HashType::SHA256,
        "SHA512" => HashType::SHA512,
        _ => return Err("Unknown hash type. Supported: SHA1/SHA256/SHA512. Requested: ".to_string() + crypto_function[1] + "."),
    };

    let num_of_digits = if crypto_function.len() == 3 {
        let temp_num = crypto_function[2].parse().unwrap_or(0);
        if temp_num > 10 || temp_num < 4 {
            return Err("Number of returned digits should satisfy: 4 <= num <= 10. You requested ".to_string() + crypto_function[2] + ".");
        }
        temp_num
    } else {
        0
    };

    let data_input: Vec<&str> = parsed_suite[2].split('-').collect();
    // Counters
    let     question_len:     usize = 128;
    let mut counter_len:      usize = 0;
    let mut hashed_pin_len:   usize = 0;
    let mut session_info_len: usize = 0;
    let mut timestamp_len:    usize = 0;

    let mut parsed_question_type: (QType, usize) = (QType::N, 0);
    let mut parsed_pin_sha_type: (HashType, usize);
    let mut timestamp_parsed: u64 = 0;

    for p in data_input {
        let setting: &[u8] = p.as_bytes();
        match setting[0] {
            b'q' | b'Q' => {
                match ocra_parse_question(p) {
                    Ok(expr) => {
                        parsed_question_type = expr;
                        // Mutual Challenge-Response tests fails on this verification.
                        /*if question.len() != parsed_question_type.1 {
                            return Err("Claimed and real question lengths are different.");
                        }*/
                    },
                    Err(err_str) => return Err(err_str + " Can't parse question " + p + "."),
                };
            },
            b'c' | b'C' => counter_len = 8,
            b'p' | b'P' => {
                match parse_pin_sha_type(p) {
                    Ok(expr) => {
                        parsed_pin_sha_type = expr;
                        // Here we don't care about hash type
                        // because pin already must be hashed.
                        hashed_pin_len = parsed_pin_sha_type.1;
                        if password.len() != hashed_pin_len {
                            return Err("Wrong hashed password length.".to_string());
                        }
                    },
                    Err(err_str) => return Err(err_str + " Can't parse hash " + p + "."),
                };
            },
            b's' | b'S' => {
                match parse_session_info_len(p) {
                    Ok(value) => session_info_len = value,
                    Err(err_str)    => return Err(err_str + " Wrong session info parameter " + p + "."),
                };
            },
            b't' | b'T' => {
                match parse_timestamp_format(p) {
                    Ok(value) => {
                        timestamp_parsed = num_of_time_steps / (value as u64);
                        timestamp_len = 8;
                    },
                    Err(err_str) => return Err(err_str + " Wrong timestamp parameter " + p + "."),
                };
            },
            _ => return Err("Unknown parameter ".to_string() + p + "."),
        }
    }

    let full_message_len = suite.len() + 1 + counter_len + question_len + hashed_pin_len + session_info_len + timestamp_len;
    let mut current_message_len = suite.len() + 1;

    let mut message: Vec<u8> = Vec::with_capacity(full_message_len);
    message.extend_from_slice(suite.as_bytes());
    message.push(0u8);    //Delimiter. Mandatory!
    if counter_len > 0 {
        let counter_be = counter.to_be();
        let msg_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&counter_be as *const u64 as *const u8, 8) };
        message.extend_from_slice(msg_ptr);
        current_message_len += counter_len;
    }
    if parsed_question_type.1 != 0 {
        let push_result = push_correct_question(&mut message, parsed_question_type, question);
        match push_result {
            Ok(_) => {
                current_message_len += question_len;
                message.resize(current_message_len, 0)
            },
            Err(err_str) => return Err(err_str),
        }
    } else {
        return Err("No question parameter specified or question length is 0.".to_string());
    }
    if hashed_pin_len > 0 {
        message.extend_from_slice(password);
        current_message_len += hashed_pin_len;
    }
    if session_info_len > 0 {
        let real_len = session_info.len();
        message.resize(current_message_len + session_info_len - real_len, 0);
        message.extend_from_slice(session_info);
        //current_message_len += session_info_len;
    }
    if timestamp_len > 0 {
        let timestamp_parsed_be = timestamp_parsed.to_be();
        let timestamp_ptr: &[u8] = unsafe { ::std::slice::from_raw_parts(&timestamp_parsed_be as *const u64 as *const u8, 8) };
        message.extend_from_slice(timestamp_ptr);
        //current_message_len += timestamp_len;
    }

    let result: u64 = match hotp_sha_type {
        HashType::SHA1   => hmac_and_truncate(key, message.as_slice(), num_of_digits, Sha1::new()),
        HashType::SHA256 => hmac_and_truncate(key, message.as_slice(), num_of_digits, Sha256::new()),
        HashType::SHA512 => hmac_and_truncate(key, message.as_slice(), num_of_digits, Sha512::new()),
    };

    Ok(result)
}

fn parse_session_info_len(session_info: &str) -> Result<usize, String> {
    let (_, num) = session_info.split_at(1);
    match num {
        "064" => Ok(64),
        "128" => Ok(128),
        "256" => Ok(256),
        "512" => Ok(512),
        _     => Err("Wrong session info length. Possible values: 064, 128, 256, 512.".to_string()),
    }
}

// To get timestamp for OCRA, divide current UTC time by this coefficient
fn parse_timestamp_format(timestamp: &str) -> Result<usize, String> {
    let (_, time_step) = timestamp.split_at(1);
    let (num_s, time_type) = time_step.split_at(time_step.len()-1);
    let num = num_s.parse::<usize>().unwrap_or(0);
    if num < 1 || num > 59 {
        return Err("Wrong timestamp value.".to_string());
    }
    let coefficient: usize;
    match time_type {
        "S" => coefficient = num,
        "M" => coefficient = num * 60,
        "H" => {
            if num < 49 {
                coefficient = num * 60 * 60;
            } else {
                return Err("Time interval is too big. Use H <= 48.".to_string());
            }
        },
        _ => return Err("Can't parse timestamp. S/M/H time intervals are supported.".to_string()),
    }

    return Ok(coefficient);
}

fn parse_pin_sha_type(psha: &str) -> Result<(HashType, usize), String> {
    let psha_local: String = psha.to_uppercase();
    if psha_local.starts_with("PSHA") {
        let (_, num) = psha_local.split_at(4);
        match num {
            "1" => Ok((HashType::SHA1, 20)),
            "256" => Ok((HashType::SHA256, 32)),
            "512" => Ok((HashType::SHA512, 64)),
            _ => Err("Unknown SHA hash mode.".to_string()),
        }
    } else {
        Err("Unknown hashing algorithm.".to_string())
    }
}

fn push_correct_question<'a>(message: &mut Vec<u8>, q_info: (QType, usize), question: &str) -> Result<(), String> {
    let (q_type, q_length) = q_info;
    match q_type {
        QType::A => {
            let hex_representation: String = question.as_bytes().to_hex();
            let mut hex_encoded: Vec<u8> = hex_representation.from_hex().unwrap();
            message.append(hex_encoded.by_ref());
        },
        QType::N => {
            // While RAMP is broken, let's assume, that question numbers will be short
            if question.len() > 19 {
                // That is the max number len for u64
                assert!(false, "Temporary limitation question.len() < 20 is exceeded.".to_string());
            }
            let q_as_u64: u64 = question.parse::<u64>().unwrap();
            let mut q_as_hex_str: String = format!("{:X}", q_as_u64);
            if q_as_hex_str.len() % 2 == 1 {
                q_as_hex_str.push('0');
            }
            message.append(from_hex(q_as_hex_str.as_str()).unwrap().by_ref());


            /*  See https://github.com/rust-lang/rust/issues/41793
            let q_as_int: Int = Int::from_str_radix(question, 10).expect("Can't parse your numeric question.");
            let sign = q_as_int.sign();
            if sign == -1 {
                return Err("Question number can't be negative.".to_string());
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
                    Err(_) => return Err("Unexpected error. Can't write to buffer.".to_string()),
                }
            }*/
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
fn ocra_parse_question(question: &str) -> Result<(QType, usize), String> {
    assert_eq!(question.len(), 4);
    let (type_str, len_str) = question.split_at(2);

    let data: &[u8] = type_str.as_bytes();
    assert!(data[0] == b'Q' || data[0] == b'q');
    let q_type_result: Result<QType, String> = match data[1] {
        b'a' | b'A' => Ok(QType::A),
        b'n' | b'N' => Ok(QType::N),
        b'h' | b'H' => Ok(QType::H),
        _           => Err("This question type is not supported! Use A/N/H, please.".to_string()),
    };

    if q_type_result.is_err() {
        return Err(q_type_result.err().unwrap().to_string());
    }

    let q_len_result = len_str.parse::<usize>();
    if q_len_result.is_err() {
        return Err("Can't parse question length.".to_string());
    }

    let q_len = q_len_result.unwrap();
    if q_len < 4 || q_len > 64 {
        return Err("Make sure you request question length such that 4 <= question_length <= 64.".to_string());
    }

    Ok((q_type_result.unwrap(), q_len))
}