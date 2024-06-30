#![forbid(unsafe_code)]
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

extern crate binascii;
extern crate ring;

#[cfg(test)]
mod tests;
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
            ring::digest::SHA1_OUTPUT_LEN => Option::Some(HOTPAlgorithm::HMACSHA1),
            ring::digest::SHA256_OUTPUT_LEN => Option::Some(HOTPAlgorithm::HMACSHA256),
            ring::digest::SHA512_OUTPUT_LEN => Option::Some(HOTPAlgorithm::HMACSHA512),
            _ => Option::None,
        }
    }

    pub fn get_algorithm<'a>(&self) -> ring::hmac::Algorithm {
        match *self {
            HOTPAlgorithm::HMACSHA1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            HOTPAlgorithm::HMACSHA256 => ring::hmac::HMAC_SHA256,
            HOTPAlgorithm::HMACSHA512 => ring::hmac::HMAC_SHA512,
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

        match HOTP::generate_secret(algo.digest_algorithm().output_len()) {
            Ok(secret) => Result::Ok(HOTP { secret, algorithm }),
            Err(err) => Result::Err(err),
        }
    }

    /// Loads a base32 encoded secret.
    ///
    /// # Arguments
    ///
    /// * `data` - base32 encoded secret to load.
    pub fn from_base32(data: &str) -> Result<HOTP, ()> {
        // let secret = base32::decode(base32::Alphabet::RFC4648 {padding: false}, data);
        let mut buffer = [0u8; 1024];
        let secret = match binascii::b32decode(data.as_bytes(), &mut buffer) {
            Ok(v) => v,
            Err(_) => {
                return Err(());
            }
        };

        let algorithm = HOTPAlgorithm::from_buffer_len(secret.len());
        match algorithm {
            Some(algorithm) => Result::Ok(HOTP {
                secret: Vec::from(secret),
                algorithm,
            }),
            None => Result::Err(()),
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
            Ok(_) => Result::Ok(secret),
            Err(err) => Result::Err(err),
        }
    }

    /// Exports the HOTP Secret as base32 encoded string.
    pub fn get_secret_base32(&self) -> String {
        let mut buffer = Box::new([0u8; 1024]);
        match binascii::b32encode(self.secret.as_slice(), buffer.as_mut()) {
            Ok(v) => {
                let vec = Vec::from(v);
                String::from_utf8(vec).unwrap()
            }
            Err(_) => unreachable!(),
        }
    }

    /// Generates a **O**ne **T**ime **P**assword from the provided parameters.
    ///
    /// # Arguments
    ///
    /// * `counter` - Password's counter. This counter value should never be reused for security reasons.
    /// * `digits` - Desired OTP length, this value should be at least 6.
    pub fn get_otp(&self, counter: &[u8], digits: u32) -> u32 {
        let key = ring::hmac::Key::new(self.algorithm.get_algorithm(), &self.secret);

        let hmac = ring::hmac::sign(&key, counter);
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

        TOTP {
            secret,
            time_step,
            start_time,
        }
    }

    fn get_time(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        return (now.as_secs() + self.start_time) / self.time_step;
    }

    /// Generates a time based OTP.
    ///
    /// # Arguments
    /// * `digits` - Desired OTP length, should be at least 6.
    /// * `offset` - Should be 0 for current time frame, -1 for previous, 1 for next, etc...
    pub fn get_otp(&self, digits: u32, offset: i32) -> u32 {
        let buf: &[u8] = &utils::num_to_buffer(((self.get_time() as i64) + (offset as i64)) as u64);
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
        }
        Err(_) => Option::None,
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
        Ok(otp) => Option::Some(TOTP::new(otp, time_step, time_start).get_otp(digits, 0)),
        Err(_) => Option::None,
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
pub fn validate_hotp(
    input: u32,
    validation_margin: i32,
    counter: u64,
    secret: &str,
    digits: u32,
) -> Option<bool> {
    match HOTP::from_base32(secret) {
        Ok(hotp) => {
            for i in (-validation_margin)..(validation_margin + 1) {
                let current_counter = (counter as i64) + (i as i64);
                if hotp.get_otp(&utils::num_to_buffer(current_counter as u64), digits) == input {
                    return Option::Some(true);
                }
            }
            Option::Some(false)
        }
        Err(_) => Option::None,
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
pub fn validate_totp(
    input: u32,
    validation_margin: u32,
    secret: &str,
    digits: u32,
    time_step: u64,
    time_start: u64,
) -> Option<bool> {
    match HOTP::from_base32(secret) {
        Ok(hotp) => {
            let totp = TOTP::new(hotp, time_step, time_start);
            Option::Some(totp.validate(digits, input, validation_margin))
        }
        Err(_) => Option::None,
    }
}
