use super::*;

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
fn test_hotp_from_base32() {
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
    assert_eq!(&utils::num_to_buffer(59 / STEP)[..], &[0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&utils::num_to_buffer(1111111109 / STEP)[..], &[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xec]);
    assert_eq!(&utils::num_to_buffer(1111111111 / STEP)[..], &[0, 0, 0, 0, 0x02, 0x35, 0x23, 0xed]);
    assert_eq!(&utils::num_to_buffer(1234567890 / STEP)[..], &[0, 0, 0, 0, 0x02, 0x73, 0xef, 0x07]);
    assert_eq!(&utils::num_to_buffer(2000000000 / STEP)[..], &[0, 0, 0, 0, 0x03, 0xf9, 0x40, 0xaa]);
    assert_eq!(&utils::num_to_buffer(20000000000 / STEP)[..], &[0, 0, 0, 0, 0x27, 0xbc, 0x86, 0xaa]);
}