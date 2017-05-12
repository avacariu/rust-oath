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

mod oathtest;

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
        password: &[u8], session_info: &[u8], timestamp: u64) -> Result<u64, &'a str> {
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
    let     question_len:     usize = 128;
    let mut counter_len:      usize = 0;
    let mut hashed_pin_len:   usize = 0;
    let mut session_info_len: usize = 0;
    let mut timestamp_len:    usize = 0;

    let mut parsed_question_type: (QType, usize) = (QType::N, 0);
    let mut parsed_pin_sha_type: (SType, usize);
    let mut timestamp_parsed: u64 = 0;

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
                        // Here we don't care about hash type
                        // because pin already must be hashed.
                        hashed_pin_len = parsed_pin_sha_type.1;
                        if password.len() != hashed_pin_len {
                            return Err("Wrong hashed password length.");
                        }
                    },
                    Err(_) => return Err("Can't parse hash."),
                };
            },
            b's' | b'S' => {
                match parse_session_info_len(p) {
                    Ok(value) => session_info_len = value,
                    Err(_)    => return Err("Wrong session info parameter."),
                };
            },
            b't' | b'T' => {
                match parse_timestamp_format(p) {
                    Ok(value) => {
                        timestamp_parsed = timestamp / (value as u64);
                        timestamp_len = 8;
                    },
                    Err(_) => return Err("Wrong timestamp parameter."),
                };
            },
            _ => return Err("Unknown parameter."),
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
        return Err("No question parameter specified or question length is 0.");
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
        SType::SHA1 => hotp_custom(key, message.as_slice(), num_of_digits, Sha1::new()),
        SType::SHA256 => hotp_custom(key, message.as_slice(), num_of_digits, Sha256::new()),
        SType::SHA512 => hotp_custom(key, message.as_slice(), num_of_digits, Sha512::new()),
    };

    Ok(result)
}

fn parse_session_info_len(session_info: &str) -> Result<usize, &str> {
    let (_, num) = session_info.split_at(1);
    match num {
        "064" => Ok(64),
        "128" => Ok(128),
        "256" => Ok(256),
        "512" => Ok(512),
        _     => Err("Wrong session info length. Possible values: 064, 128, 256, 512"),
    }
}

// To get timestamp for OCRA, divide current UTC time by this coefficient
fn parse_timestamp_format(timestamp: &str) -> Result<usize, &str> {
    let (_, time_step) = timestamp.split_at(1);
    let (num_s, time_type) = time_step.split_at(time_step.len()-1);
    let num = num_s.parse::<usize>().unwrap_or(0);
    if num < 1 || num > 59 {
        return Err("Wrong timestamp value.");
    }
    let coefficient: usize;
    match time_type {
        "S" => coefficient = num,
        "M" => coefficient = num * 60,
        "H" => {
            if num < 49 {
                coefficient = num * 60 * 60;
            } else {
                return Err("Time interval is too big. Use H <= 48");
            }
        },
        _ => return Err("Can't parse timestamp. S/M/H time intervals are supported."),
    }

    return Ok(coefficient);
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