
mod rc5;
mod utils;
mod word;

use crate::rc5::RC5;

/// Returns a cipher text for a given key and plaintext
fn encode_rc5(
			word_size_in_bits: usize,
			num_rounds:u8,
			key_size:u8,
			key: &[u8],
			plaintext: &[u8]

			) -> Vec<u8> {

	let rc5 = RC5::new(word_size_in_bits, num_rounds, key_size);
	rc5.encrypt(&key, &plaintext)
}

/// Returns a plaintext for a given key and ciphertext
fn decode_rc5(
			word_size_in_bits: usize,
			num_rounds:u8,
			key_size:u8,
			key: &[u8],
			ciphertext: &[u8]

			) -> Vec<u8> {

	let rc5 = RC5::new(word_size_in_bits, num_rounds, key_size);
	rc5.decrypt(&key,&ciphertext)
}

#[cfg(test)]
mod rc5_32_12_16_tests {
	use super::*;

	#[test]
    fn encode_decode() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x23, 0xfe, 0xa0, 0x11, 0x89, 0x55, 0x10, 0x02];
    	let res = encode_rc5(32, 12, 16, &key, &pt);
		let res = decode_rc5(32, 12, 16, &key, &res);
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn encode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
    	let res = encode_rc5(32, 12, 16, &key, &pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
    	let res = encode_rc5(32, 12, 16, &key, &pt);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
    	let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    	let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let res = decode_rc5(32, 12, 16, &key, &ct);
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
		let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    	let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let res = decode_rc5(32, 12, 16, &key, &ct);
    	assert!(&pt[..] == &res[..]);
    }
}

#[cfg(test)]
mod rc5_8_12_4_tests {
	use super::*;

	#[test]
    fn encode() {
    	let key = vec![0x00, 0x01, 0x02, 0x03];
    	let pt  = vec![0x00, 0x01];
		let ct  = vec![0x21, 0x2A];
    	let res = encode_rc5(8, 12, 4, &key, &pt);
    	assert!(&ct[..] == &res[..]);
    }
}

#[cfg(test)]
mod rc5_16_16_8_tests {
	use super::*;

	#[test]
	fn encode() {
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		let pt  = vec![0x00, 0x01, 0x02, 0x03];
		let ct  = vec![0x23, 0xA8, 0xD7, 0x2E];
		let res = encode_rc5(16, 16, 8, &key, &pt);
		assert!(&ct[..] == &res[..]);
	}
}

#[cfg(test)]
mod rc5_32_20_16_tests {
	use super::*;

	#[test]
	fn encode() {
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		let ct = vec![0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
		let res = encode_rc5(32, 20, 16, &key, &pt);
		assert!(&ct[..] == &res[..]);
	}
}

#[cfg(test)]
mod rc5_64_24_24_tests {
	use super::*;

	#[test]
	fn encode_decode() {
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
		let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
		let ct = vec![0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71, 0x78, 0xDA];
		let res = encode_rc5(64, 24, 24, &key, &pt);
		assert!(&ct[..] == &res[..]);

		let res = decode_rc5(64, 24, 24, &key, &res);
		assert!(&pt[..] == &res[..]);
	}
}

#[cfg(test)]
mod rc5_128_28_32_tests {
	use super::*;

	#[test]
	fn encode_decode() {
		let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
		let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
		let ct = vec![0xEC, 0xA5, 0x91, 0x09, 0x21, 0xA4, 0xF4, 0xCF, 0xDD, 0x7A, 0xD7, 0xAD, 0x20, 0xA1, 0xFC, 0xBA, 0x06, 0x8E, 0xC7, 0xA7, 0xCD, 0x75, 0x2D, 0x68, 0xFE, 0x91, 0x4B, 0x7F, 0xE1, 0x80, 0xB4, 0x40];
		let res = encode_rc5(128, 28, 32, &key, &pt);
		assert!(&ct[..] == &res[..]);

		let res = decode_rc5(128, 28, 32, &key, &res);
		assert!(&pt[..] == &res[..]);
	}
}
