//! HMAC and Time-Based One-Time-Password implementations based on RFC4226 and RFC6238.
//!
//! # Examples
//! ```
//! use libotp::{totp, validate_totp};
//!
//! const TOTP_STEP: u64 = 30;
//! const OTP_DIGITS: u32 = 8;
//! #
//! # struct User {}
//! # impl<'a> User {
//! #     fn get_totp_secret(&self) -> &'a str {
//! #         "SomeBase32EncodedSecret"
//! #     }
//! # }
//!
//! fn check_user_otp(user: User, guess: u32) -> Option<bool> {
//!     // get the shared secret from some database.
//!     let secret = user.get_totp_secret();
//!
//!     validate_totp(guess, 1, secret, OTP_DIGITS, TOTP_STEP, 0)
//! }
//!
//! fn get_user_otp(user: User) -> Option<u32> {
//!     // get shared secret
//!     let secret = user.get_totp_secret();
//!
//!     totp(secret, OTP_DIGITS, TOTP_STEP, 0)
//! }
//! ```

extern crate ring;
extern crate base32;

mod utils;

#[derive(Copy, Clone)]
pub enum HOTPAlgorithm {
    HMACSHA1,
    HMACSHA256,
    HMACSHA512,
}

impl HOTPAlgorithm {
    pub fn from_buffer_len(buffer_length: usize) -> Option<HOTPAlgorithm> {
        match buffer_length {
            ring::digest::SHA1_OUTPUT_LEN => {
                Option::Some(HOTPAlgorithm::HMACSHA1)
            },
            ring::digest::SHA256_OUTPUT_LEN => {
                Option::Some(HOTPAlgorithm::HMACSHA256)
            },
            ring::digest::SHA512_OUTPUT_LEN => {
                Option::Some(HOTPAlgorithm::HMACSHA512)
            },
            _ => {
                Option::None
            },
        }
    }

    pub fn get_algorithm<'a>(&self) -> &'a ring::digest::Algorithm {
        match *self {
            HOTPAlgorithm::HMACSHA1 => &ring::digest::SHA1,
            HOTPAlgorithm::HMACSHA256 => &ring::digest::SHA256,
            HOTPAlgorithm::HMACSHA512 => &ring::digest::SHA512,
        }
    }
}

/// This is the secret that will be used to generate HMAC based one-time-passwords.
///
/// # References
/// * This object implements utilities for [RFC4226](https://tools.ietf.org/html/rfc4226).
pub struct HOTP {
    secret: Vec<u8>,
    algorithm: HOTPAlgorithm,
}

impl HOTP {
    /// Creates a new HOTPSecret from OS generated random number.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Algorithm to use for OTP generation.
    pub fn new(algorithm: HOTPAlgorithm) -> Result<HOTP, ring::error::Unspecified> {
        let algo = algorithm.get_algorithm();

        match HOTP::generate_secret(algo.output_len) {
            Ok(secret) => {
                Result::Ok(HOTP {
                    secret,
                    algorithm,
                })
            },
            Err(err) => {
                Result::Err(err)
            }
        }
    }

    /// Loads a base32 encoded secret.
    ///
    /// # Arguments
    ///
    /// * `data` - base32 encoded secret to load.
    pub fn from_base32(data: &str) -> Result<HOTP, ()> {
        let secret = base32::decode(base32::Alphabet::RFC4648 {padding: false}, data);

        match secret {
            Some(secret) => {
                let algorithm = HOTPAlgorithm::from_buffer_len(secret.len());
                match algorithm {
                    Some(algorithm) => {
                        Result::Ok(HOTP{
                            secret,
                            algorithm,
                        })
                    },
                    None => {
                        Result::Err(())
                    }
                }
            },
            None => {
                Result::Err(())
            }
        }
    }

    /// Loads the HOTP secret from a given `[u8]`.
    ///
    /// # Arguments
    /// * `data` - The shared secret.
    /// * `algorithm` - Algorithm used for OTP generation.
    pub fn from_bin(data: &[u8]) -> Result<HOTP, ()> {
        let algorithm = HOTPAlgorithm::from_buffer_len(data.len());
        if algorithm.is_none() {
            return Result::Err(());
        }
        Result::Ok(HOTP {
            secret: Vec::from(data),
            algorithm: algorithm.unwrap(),
        })
    }

    fn generate_secret(size: usize) -> Result<Vec<u8>, ring::error::Unspecified> {
        use ring::rand::SecureRandom;

        let mut secret: Vec<u8> = vec![0; size];
        let rand = ring::rand::SystemRandom::new();

        match rand.fill(secret.as_mut()) {
            Ok(_) => {
                Result::Ok(secret)
            },
            Err(err) => {
                Result::Err(err)
            }
        }
    }

    /// Exports the HOTP Secret as base32 encoded string.
    pub fn get_secret_base32(&self) -> String {
        base32::encode(base32::Alphabet::RFC4648{padding: false}, self.secret.as_slice())
    }

    /// Generates a **O**ne **T**ime **P**assword from the provided parameters.
    ///
    /// # Arguments
    ///
    /// * `counter` - Password's counter. This counter value should never be reused for security reasons.
    /// * `digits` - Desired OTP length, this value should be at least 6.
    pub fn get_otp(&self, counter: &[u8], digits: u32) -> u32 {
        let algorithm = self.algorithm.get_algorithm();

        let signer = ring::hmac::SigningKey::new(algorithm, self.secret.as_slice());
        let hmac = ring::hmac::sign(&signer, counter);
        let block = hmac.as_ref();
        let num = HOTP::get_hotp_value(block);

        return num % 10u32.pow(digits);
    }

    fn get_hotp_value(data: &[u8]) -> u32 {
        let offset: usize = (data[data.len() - 1] & 0x0f) as usize;

        let result: u32 = (((data[offset] & 0x7f) as u32) << 24)
            | (((data[offset + 1] & 0xff) as u32) << 16)
            | (((data[offset + 2] & 0xff) as u32) << 8)
            | ((data[offset + 3] & 0xff) as u32);
        return result;
    }

    /// Validates the given OTP
    ///
    /// # Arguments
    /// * `counter` - The counter to test against.
    /// * `digits` - The OTPs length.
    /// * `guess` - A user provided guess to validate.
    ///
    /// # Note
    /// It is recommended to check the following counters in case the user skipped an OTP.
    /// You should verify that an OTP with the same counter was not already used.
    pub fn validate(&self, counter: &[u8], digits: u32, guess: u32) -> bool {
        self.get_otp(counter, digits) == guess
    }
}

/// Provides Time based One Time Passwords.
///
/// # References
/// * This object implements utilities for [RFC6328](https://tools.ietf.org/html/rfc6238).
pub struct TOTP {
    secret: HOTP,
    time_step: u64,
    start_time: u64,
}

impl TOTP {
    /// Creates a new TOTP instance.
    ///
    /// # Arguments
    /// * `secret` - HOTP secret to use for TOTP generation.
    /// * `time_step` - The time frame to allow every password, in seconds. RFC6238 recommends 30 seconds.
    /// * `start_time` - Configurable T0 for OTP.
    pub fn new(secret: HOTP, time_step: u64, start_time: u64) -> TOTP {
        assert!(time_step > 0);

        TOTP{
            secret,
            time_step,
            start_time,
        }
    }

    fn get_time(&self) -> u64 {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        return (now.as_secs() + self.start_time) / self.time_step;
    }

    /// Generates a time based OTP.
    ///
    /// # Arguments
    /// * `digits` - Desired OTP length, should be at least 6.
    /// * `offset` - Should be 0 for current time frame, -1 for previous, 1 for next, etc...
    pub fn get_otp(&self, digits: u32, offset: i32) -> u32 {
        let buf: &[u8] = &utils::num_to_buffer(((self.get_time() as i64) + (offset as i64)) as u64 );
        return self.secret.get_otp(buf, digits);
    }

    /// Validates the given OTP.
    ///
    /// # Arguments
    /// * `digits` - The amount of digits set for the OTP.
    /// * `guess` - The user provided guess to validate.
    /// * `buffer` - Amount of OTPs to check before and after the current one (0=Only current, 1=Previous+Now+Next OTP, etc...)
    pub fn validate(&self, digits: u32, guess: u32, buffer: u32) -> bool {
        for offset in -(buffer as i32)..((buffer + 1) as i32) {
            if self.get_otp(digits, offset) == guess {
                return true;
            }
        }
        return false;
    }
}

/// HMAC One Time Password function
///
/// # Arguments
/// * `counter` - A 64-bit counter for HOTP
/// * `secret` - A base32 encoded secret
/// * `digits` - Desired OTP length in digits. 6+ is recommended.
///
/// # Notes
/// This function converts the counter to it's 64 bit little endian representation.
/// If you have other requirements, please use the HOTP struct directly.
pub fn hotp(counter: u64, secret: &str, digits: u32) -> Option<u32> {
    match HOTP::from_base32(secret) {
        Ok(otp) => {
            let counter_bytes = &utils::num_to_buffer(counter);
            Option::Some(otp.get_otp(counter_bytes, digits))
        },
        Err(_) => {
            Option::None
        }
    }
}

/// Time based One Time Password function
///
/// # Arguments
/// * `secret` - base32 encoded shared-secret.
/// * `digits` - Desired OTP length in digits. 6+ is recommended.
/// * `time_step` - Time frame for OTP is seconds.
/// * `time_start` - Beginning of time for this TOTP.
///
/// # Example Usage
/// ```
/// use libotp::totp;
/// const MY_SECRET: &str = "VMNW2EC7X3OCJHITBVSVZW5MVCUIL5SR";
///
/// fn main() {
///     match totp(MY_SECRET, 6, 30, 0) {
///         Some(otp) => {
///             println!("Your current OTP is: {:06}", otp);
///         },
///         None => {
///             println!("Failed to calculate OTP.");
///         }
///     }
/// }
/// ```
pub fn totp(secret: &str, digits: u32, time_step: u64, time_start: u64) -> Option<u32> {
    match HOTP::from_base32(secret) {
        Ok(otp) => {
            Option::Some(TOTP::new(otp, time_step, time_start).get_otp(digits, 0))
        },
        Err(_) => {
            Option::None
        }
    }
}

/// Validates HOTP inputs
///
/// # Arguments
/// * `input` - End user's input
/// * `validation_margin` - The validation will check this amount of OTPs before and after the current one.
/// * `counter` - End user's currnet OTP counter.
/// * `secret` - base32 encoded shared-secret.
/// * `digits` - OTP length in digits. At least 6 is recommended.
///
/// # Notes
/// The program using this function should check that the provided input was not already used.
pub fn validate_hotp(input: u32, validation_margin: i32, counter: u64, secret: &str, digits: u32) -> Option<bool> {
    match HOTP::from_base32(secret) {
        Ok(hotp) => {
            for i in (-validation_margin)..(validation_margin+1) {
                let current_counter = (counter as i64) + (i as i64);
                if hotp.get_otp(&utils::num_to_buffer(current_counter as u64), digits) == input {
                    return Option::Some(true);
                }
            }
            Option::Some(false)
        },
        Err(_) => {
            Option::None
        }
    }
}

/// Validates a user provided TOTP.
///
/// # Arguments
/// * `input` - End user provided input
/// * `validation_margin` - Checks this amount of OTP steps before and after the current OTP.
/// * `secret` - A base32 encoded shared-secret.
/// * `digits` - OTP length in digits. At least 6 is recommended.
/// * `time_step` - Time frame for OTPs.
/// * `time_start` - The beginning of time for this OTP (T0).
pub fn validate_totp(input: u32, validation_margin: u32, secret: &str, digits: u32, time_step: u64, time_start: u64) -> Option<bool> {
    match HOTP::from_base32(secret) {
        Ok(hotp) => {
            let totp = TOTP::new(hotp, time_step, time_start);
            Option::Some(totp.validate(digits, input, validation_margin))
        },
        Err(_) => {
            Option::None
        }
    }
}

#[test]
fn test_gen_secret() {
    let hotp_sha1 = HOTP::new(HOTPAlgorithm::HMACSHA1).unwrap();
    assert_eq!(hotp_sha1.secret.len(), 20);

    let hotp_sha256 = HOTP::new(HOTPAlgorithm::HMACSHA256).unwrap();
    assert_eq!(hotp_sha256.secret.len(), 32);

    let hotp_sha512 = HOTP::new(HOTPAlgorithm::HMACSHA512).unwrap();
    assert_eq!(hotp_sha512.secret.len(), 64);
}

#[test]
fn test_hotp_from_bin() {
    // SHA1
    HOTP::from_bin(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14]).unwrap();

    // SHA256
    HOTP::from_bin(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26]).unwrap();

    // SHA512
    HOTP::from_bin(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
        0x3d, 0x3e, 0x3f, 0x40]).unwrap();
}

#[test]
fn test_hotm_from_base32() {
    HOTP::from_base32("AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYU").unwrap();
    HOTP::from_base32("AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYUCULBOGAZDINRYHI6D4QA====").unwrap();
    HOTP::from_base32("AEBAGBAFAYDQQCIKBMGA2DQPCAIREEYUCULBOGAZDINRYHI6D4QCCIRDEQSSMJZIFEVCWLBNFYXTAMJSGM2DKNRXHA4TUOZ4HU7D6QA=").unwrap();
}

#[test]
fn test_dynamic_trunc() {
    let num = HOTP::get_hotp_value(&[31, 134, 152, 105, 14, 2, 202, 22, 97, 133, 80, 239, 127, 25, 218, 142, 148, 91, 85, 90]);
    assert_eq!(num, 0x50ef7f19);
}

#[test]
fn test_secret() {
    let hotp_sha1 = HOTP {
        secret: vec!(0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30),
        algorithm: HOTPAlgorithm::HMACSHA1,
    };
    let hotp_sha256 = HOTP {
        secret: vec!(0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                     0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32),
        algorithm: HOTPAlgorithm::HMACSHA256,
    };
    let hotp_sha512 = HOTP {
        secret: vec!(0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                     0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                     0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
                     0x31, 0x32, 0x33, 0x34),
        algorithm: HOTPAlgorithm::HMACSHA512,
    };

    assert_eq!(hotp_sha1.get_otp(&[0, 0, 0, 0, 0, 0, 0, 1], 8), 94287082);
    assert_eq!(hotp_sha256.get_otp(&[0, 0, 0, 0, 0, 0, 0, 1], 8), 46119246);
    assert_eq!(hotp_sha512.get_otp(&[0, 0, 0, 0, 0, 0, 0, 1], 8), 90693936);
    assert_eq!(hotp_sha1.get_otp(&[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec], 8), 7081804);
    assert_eq!(hotp_sha256.get_otp(&[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec], 8), 68084774);
    assert_eq!(hotp_sha512.get_otp(&[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec], 8), 25091201);
    assert_eq!(hotp_sha1.get_otp(&[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xed], 8), 14050471);
    assert_eq!(hotp_sha256.get_otp(&[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xed], 8), 67062674);
    assert_eq!(hotp_sha512.get_otp(&[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xed], 8), 99943326);
    assert_eq!(hotp_sha1.get_otp(&[0, 0, 0, 0, 0x02, 0x73, 0xef, 0x07], 8), 89005924);
    assert_eq!(hotp_sha256.get_otp(&[0, 0, 0, 0, 0x02, 0x73, 0xef, 0x07], 8), 91819424);
    assert_eq!(hotp_sha512.get_otp(&[0, 0, 0, 0, 0x02, 0x73, 0xef, 0x07], 8), 93441116);
    assert_eq!(hotp_sha1.get_otp(&[0, 0, 0, 0, 0x03, 0xf9, 0x40, 0xaa], 8), 69279037);
    assert_eq!(hotp_sha256.get_otp(&[0, 0, 0, 0, 0x03, 0xf9, 0x40, 0xaa], 8), 90698825);
    assert_eq!(hotp_sha512.get_otp(&[0, 0, 0, 0, 0x03, 0xf9, 0x40, 0xaa], 8), 38618901);
    assert_eq!(hotp_sha1.get_otp(&[0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa], 8), 65353130);
    assert_eq!(hotp_sha256.get_otp(&[0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa], 8), 77737706);
    assert_eq!(hotp_sha512.get_otp(&[0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa], 8), 47863826);
}

#[test]
fn test_time_to_counter() {
    const STEP: u64 = 30;
    assert_eq!(&utils::num_to_buffer((59 / STEP))[..], &[0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&utils::num_to_buffer((1111111109 / STEP))[..], &[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec]);
    assert_eq!(&utils::num_to_buffer((1111111111 / STEP))[..], &[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xed]);
    assert_eq!(&utils::num_to_buffer((1234567890 / STEP))[..], &[0, 0, 0, 0, 0x02, 0x73, 0xef, 0x07]);
    assert_eq!(&utils::num_to_buffer((2000000000 / STEP))[..], &[0, 0, 0, 0, 0x03, 0xf9, 0x40, 0xaa]);
    assert_eq!(&utils::num_to_buffer((20000000000 / STEP))[..], &[0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa]);
}
