use std::convert::TryInto;


fn permutation(input: u64, index_perm: &[u8]) -> u64 {
    let mut ret = 0_u64;

    let input_mask = 0x80_00_00_00_00_00_00_00_u64;

    for i in 0..index_perm.len() {

        let a = index_perm[i] - 1;

        if input&(input_mask>> a) > 0 {
            ret |= (input_mask) >> i;
        }
    }

    let a = ret;

    ret
}

fn initial_permutation(input: u64) -> u64 {
    let index_perm = vec![58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
    permutation(input, &index_perm)
}

fn final_permutation(input: u64) -> u64 {
    let index_perm = vec![40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
    permutation(input, &index_perm)
}

/// the 32-bit half-block is expanded to 48 bits.
fn expansion_function(input: u64) -> u64 {
    let index_perm = vec![32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
    permutation(input, &index_perm)
}

/// shuffles the bits of a 32-bit half-block
fn shuffle(input: u64) -> u64 {
    let index_perm = vec![16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5,	18,	31,	10, 2, 8, 24, 14, 32, 27, 3, 9, 19,	13,	30,	6, 22, 11, 4, 25];
    permutation(input, &index_perm)
}

fn permuted_choice_1(input: u64) -> u64 {
    let index_perm = vec![57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
    permutation(input, &index_perm)
}

/// This permutation selects the 48-bit subkey for each 
/// round from the 56-bit key-schedule state.
/// This permutation will ignore 8 bits below:
/// Permuted Choice 2 "PC-2" Ignored bits 9, 18, 22, 25, 35, 38, 43, 54.
fn permuted_choice_2(input: u64) -> u64 {
    let index_perm = vec![14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
    permutation(input, &index_perm)
}

/// Create 16 subkeys, each of which is 48-bits long.
fn generate_subkeys(key: u64) -> Vec<u64> {

    let mut ret = Vec::new();

    // println!("Input key {:#064b}", key);

    // In k we will have 56-bit permutation. Only the msb 56 bit are considered.
    let k = permuted_choice_1(key);

    // println!("K {:#064b}", k);

    let c0 = k & generate_mask(28);
    let d0 = k<<28 & generate_mask(28);

    // println!("Previous {:#064b} {:#064b}", c0, d0);

    let shift_left_per_round = [1_u8, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    let mut ci = c0;
    let mut di = d0;
    for num_round in 0..16 {
        ci = left_shift(ci,
                                shift_left_per_round[num_round],
                                28);

        di = left_shift(di,
                                 shift_left_per_round[num_round],
                                 28);

        // println!("{} {:#064b} {:#064b}", (num_round+1), ci, di);

        let ci_di = ci | (di>>28); // ci_di contains a 56-bit partial key
        let ki = permuted_choice_2(ci_di); // ki contains the 48-bit subkey

        ret.push(ki);
    }

    // Validated with https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

    ret
}

/// Generates a mask with the specified number of 1's on the msb position
fn generate_mask(num_bits: u8) -> u64 {
    let mut ret = 0_u64;

    let partial_mask = 0x80_00_00_00_00_00_00_00_u64;
    for i in 0..num_bits {
        ret |= partial_mask >>i;
    }

    ret
}

fn left_shift(input: u64, shift_amount: u8, num_bits: u8) -> u64 {
    let left = input << shift_amount;
    let right = input >> (num_bits - shift_amount);

    (left | right) & generate_mask(num_bits)
}

fn expansion(input: u64) -> u64 {
    let index_perm = vec![32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
    permutation(input, &index_perm)
}

fn s_box(num_box:usize, x:usize, y:usize) -> u8 {

    let s1 = [[14_u8, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]];

    let s2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]];

    let s3 = [[10_u8, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]];

    let s4 = [[7_u8, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]];

    let s5 = [[2_u8, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]];

    let s6 = [[12_u8, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]];

    let s7 = [[4_u8, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]];

    let s8 = [[13_u8, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]];

    let boxes = [s1, s2, s3, s4, s5, s6, s7, s8];

    boxes[num_box][y][x]
}

/// Operates on two blocks, one of 32 bits and one of
/// 48 bits, and produces a block of 32 bits. 
fn feistel (half: u64, subkey: u64) -> u64 {
    // Expansion
    let expanded = expansion(half);

    // Key mixing
    let mixed = expanded ^ subkey;

    // Substitution
    let mut ret = 0_u64;
	for num_box in 0..8_usize {
		// Only consider the 6 bits for each box input
		let mut box_input = mixed >> (58 - 6*num_box);
		box_input &= 0x3F;

		let x = (box_input & 0x1E) >> 1 ;
		let y = (box_input&0x20)>>4 | (box_input & 0x01);

		let box_output = s_box(num_box.try_into().unwrap(), 
                                x.try_into().unwrap(), 
                                y.try_into().unwrap());

		ret |= (box_output as u64) << (60 - (4 * num_box))
	}

    // Permutation
    let index_perm = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
    permutation(ret, &index_perm)

}

fn encrypt(input: u64, key: u64) -> u64 {
    encrypt_or_decrypt(input, key, true)
}

pub fn decrypt(input: u64, key: u64) -> u64 {
    encrypt_or_decrypt(input, key, false)
}

/// Both encryption and decryption procedures share the
/// same algorithm. It only varies in the order the partial
/// keys are applied.
fn encrypt_or_decrypt(input: u64, key: u64, encrypt: bool) -> u64 {
    enum Range {
        // This is to unify the std::ops::Range<_> & std::iter::Rev<std::ops::Range<_>>
        // to the same 'Range' type
        Forward(std::ops::Range<usize>),
        Backwards(std::iter::Rev<std::ops::Range<usize>>),
    }
    impl Iterator for Range {
        type Item = usize;
        fn next(&mut self) -> Option<usize> {
            match self {
                Range::Forward(range) => range.next(),
                Range::Backwards(range) => range.next(),
            }
        }
    }

    let ini_per_res = initial_permutation(input);

    let l0 = ini_per_res & generate_mask(32);
    let r0 = ini_per_res<<32 & generate_mask(32);

    let subkeys = generate_subkeys(key);

    let mut li = l0;
    let mut ri = r0;

    let range = if encrypt {
        Range::Forward(0..16)
    }
    else {
        Range::Backwards((0..16).rev())
    };

    for num_iteration in range {
        let kn = subkeys.get(num_iteration).unwrap();

        let prev_li = li;
        li = ri;
        ri = prev_li ^ feistel(ri, *kn);
    }

    final_permutation(ri | (li>>32))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_feistel_function() {
        // https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        let input_key = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001_u64;
        let subkeys = generate_subkeys(input_key);
        let expected = 0b0010001101001010101010011011101100000000000000000000000000000000_u64;
        let r0 = 0b11110000101010101111000010101010_00000000_00000000_00000000_00000000_u64;
        assert_eq!(expected, feistel(r0, *subkeys.get(0).unwrap()));
    }

    #[test]
    fn test_expansion() {
        // https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        let input = 0b1111000010101010111100001010101000000000000000000000000000000000_u64;
        let expected = 0b011110100001010101010101011110100001010101010101_00000000_00000000_u64;
        assert_eq!(expected, expansion(input));
    }

    #[test]
    fn test_subkeys_generation() {
        // https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        let input_key = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001_u64;
        let subkeys = generate_subkeys(input_key);
        let expected = 0b1100101100111101100010110000111000010111111101010000000000000000_u64;
        assert_eq!(expected, *subkeys.get(15).unwrap());
    }

    #[test]
    fn test_permut_choice_1() {
        // https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        let input = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001_u64;
        let expected = 0b1111000011001100101010101111010101010110011001111000111100000000_u64;
        assert_eq!(expected, permuted_choice_1(input));
    }

    #[test]
    fn test_permutation() {
        let input = 0b00000000_00000000_00000000_00000000_00000000_00000000_00000000_01000000_u64;
        let expected = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;
        assert_eq!(expected, initial_permutation(input));

        let input = 0b00000010_00000000_00000000_00000000_00000000_00000000_00000000_00000000_u64;
        let expected = 0b00000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001_u64;
        assert_eq!(expected, initial_permutation(input));
    }

    #[test]
    fn test_mask() {
        assert_eq!(0, generate_mask(0));
        assert_eq!(0x80_00_00_00_00_00_00_00_u64, generate_mask(1));
        assert_eq!(0xFFFFFFF000000000_u64, generate_mask(28));
        assert_eq!(0xFFFFFFFFFFFFFFFF_u64, generate_mask(64));
    }

    #[test]
    fn test_left_shift() {
        let expected = 0x2000001000000000_u64;
        let input = 0x90_00_00_00_00_00_00_00_u64;
        assert_eq!(expected, left_shift(input, 1, 28));

        let expected = 0x4000002000000000_u64;
        let input = 0x90_00_00_00_00_00_00_00_u64;
        assert_eq!(expected, left_shift(input, 2, 28));
    }

    #[test]
    fn test_initial_final_permut() {
        let input = 0x80_01_3F_00_D0_23_77_9A_u64;
        assert_eq!(input, final_permutation(initial_permutation(input)));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let input = 123123_u64;
        let key = 112312323123_u64;
        assert_eq!(input, decrypt(encrypt(input, key), key));
    }

    #[test]
    fn test_encrypt() {
        // https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
        let input = 0x0123456789ABCDEF_u64;
        let key = 0x133457799BBCDFF1_u64;
        assert_eq!(0x85E813540F0AB405_u64, encrypt(input, key));
    }
}