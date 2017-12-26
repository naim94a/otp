extern crate rand;
extern crate ring;
extern crate base32;

mod utils;

#[derive(Copy, Clone)]
pub enum HOTPAlgorithm {
    HMACSHA1,
    HMACSHA256,
    HMACSHA512,
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
    pub fn new(algorithm: HOTPAlgorithm) -> Result<HOTP, std::io::Error> {
        let algo = HOTP::get_algorithm(algorithm);

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

    fn get_algorithm<'a>(algorithm: HOTPAlgorithm) -> &'a ring::digest::Algorithm {
        match algorithm {
            HOTPAlgorithm::HMACSHA1 => &ring::digest::SHA1,
            HOTPAlgorithm::HMACSHA256 => &ring::digest::SHA256,
            HOTPAlgorithm::HMACSHA512 => &ring::digest::SHA512,
        }
    }

    /// Loads a base32 encoded secret.
    ///
    /// # Arguments
    ///
    /// * `data` - base32 encoded secret to load.
    pub fn from_base32(data: &str, algorithm: HOTPAlgorithm) -> Result<HOTP, ()> {
        let secret = base32::decode(base32::Alphabet::RFC4648 {padding: false}, data);
        match secret {
            Some(secret) => {
                Result::Ok(HOTP {
                    secret,
                    algorithm,
                })
            },
            None => {
                Result::Err(())
            }
        }
    }

    pub fn from_bin(data: &[u8], algorithm: HOTPAlgorithm) -> HOTP {
        HOTP {
            secret: Vec::from(data),
            algorithm,
        }
    }

    fn generate_secret(size: usize) -> Result<Vec<u8>, std::io::Error> {
        use rand::Rng;

        match rand::OsRng::new() {
            Ok(mut rng) => {
                let mut secret: Vec<u8> = Vec::with_capacity(size);

                for _ in 0..size {
                    secret.push( rng.next_u32() as u8 );
                }

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
        let algorithm = HOTP::get_algorithm(self.algorithm);

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
