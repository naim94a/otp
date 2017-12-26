
fn get_byte_at(num: u64, idx: u32) -> u8 {
    let bits_offset = idx * 8;
    let byte_mask: u64 = 0xff << bits_offset;

    ((num & byte_mask) >> bits_offset) as u8
}

pub fn num_to_buffer(number: u64) -> [u8; 8] {
    let num = number.to_le();

    [
        get_byte_at(num, 7),
        get_byte_at(num, 6),
        get_byte_at(num, 5),
        get_byte_at(num, 4),
        get_byte_at(num, 3),
        get_byte_at(num, 2),
        get_byte_at(num, 1),
        get_byte_at(num, 0),
    ]
}

#[test]
fn test_byte_at() {
    const RESULT : &[u8; 8] = &[0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb, 0xed, 0x0f];
    const TEST: u64 = 0x0fedcba987654321;
    for i in 0..8 {
        assert_eq!(get_byte_at(TEST, i), RESULT[i as usize]);
    }
}

#[test]
fn test_num_to_buf() {
    const NUMBER: u64 = 0x0f00000000000001;

    assert_eq!(&num_to_buffer(NUMBER)[..], &[0x0f, 0, 0, 0, 0, 0, 0, 0x01]);
}