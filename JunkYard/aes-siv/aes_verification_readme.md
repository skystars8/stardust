
# Verifying AES Implementation in Rust

This guide provides detailed instructions on how to verify the correctness of an AES encryption implementation in Rust. By using well-known test vectors, you can ensure that your AES algorithm is working properly and producing expected results.

## Why Verification Is Important
To make sure your AES encryption implementation is functioning correctly, it is important to use standardized test vectors. These vectors, provided by standards organizations like NIST (National Institute of Standards and Technology), help to ensure that your algorithm is producing identical outputs for given inputs, which is critical for reliable encryption.

## How to Test AES Implementation

To ensure your AES encryption algorithm in Rust is correct, you can use **test vectors** provided by standards organizations like NIST. Test vectors include known values for the key, plaintext, and the expected ciphertext. By comparing your output to these expected values, you can verify the correctness of your implementation.

### 1. Use NIST AES Test Vectors

The **NIST Special Publication 800-38A** provides detailed test vectors for AES in different modes, such as ECB, CBC, and CFB. Typically, each test vector includes:
- **Key**: The symmetric key used for encryption.
- **Plaintext**: The input data that needs to be encrypted.
- **Ciphertext**: The expected encrypted output.

If your implementation produces the same ciphertext for a given key and plaintext as defined in these test vectors, your AES implementation is correct.

You can find the NIST AES test vectors at:
- [NIST AES Test Vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#test-vectors)

### 2. Example AES-128 Test Vector

Here is a commonly used test vector for AES-128 in ECB mode:

- **Key**: `2b7e151628aed2a6abf7158809cf4f3c`
- **Plaintext**: `6bc1bee22e409f96e93d7e117393172a`
- **Expected Ciphertext**: `3ad77bb40d7a3660a89ecaf32466ef97`

To verify your implementation, encrypt the given plaintext with the given key and check if your output matches the expected ciphertext. If they match, your encryption function is correct.

### 3. Rust Example to Use the Test Vector

Assuming you are using a crate like [`aes`](https://crates.io/crates/aes) or [`aes-gcm`](https://crates.io/crates/aes-gcm), here is an example of how to implement a test case:

```rust
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use hex_literal::hex;

// Type alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn main() {
    // Define the key, plaintext, and expected ciphertext as hex values
    let key = hex!("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex!("000102030405060708090a0b0c0d0e0f"); // Example IV
    let plaintext = hex!("6bc1bee22e409f96e93d7e117393172a");
    let expected_ciphertext = hex!("7649abac8119b246cee98e9b12e9197d");

    // Create an AES-128 CBC instance with the key and IV
    let cipher = Aes128Cbc::new_from_slices(&key, &iv).unwrap();

    // Encrypt the plaintext
    let ciphertext = cipher.encrypt_vec(&plaintext);

    // Verify the result matches the expected ciphertext
    assert_eq!(ciphertext, expected_ciphertext);
    println!("AES encryption test passed!");
}
```

In this example:
- **Key**, **IV**, **Plaintext**, and **Expected Ciphertext** are defined in hexadecimal format.
- The `assert_eq!` macro is used to verify if your ciphertext matches the expected value.

### 4. Common Testing Approach

- **Automated Testing**: Write a set of unit tests using the Rust `#[test]` attribute. Include multiple test vectors, different AES modes (ECB, CBC, etc.), and different key sizes (AES-128, AES-192, AES-256).
- **Decrypt and Compare**: Encrypt the plaintext and verify the ciphertext matches the expected value. Similarly, decrypt the ciphertext and verify it matches the original plaintext.
- **Cross-Verify**: Encrypt data with your Rust implementation and compare it with the output of a known good implementation, like OpenSSL or other cryptographic tools.

## Resources for Test Vectors

Here are some resources where you can find standardized AES test vectors:

- **NIST CAVP (Cryptographic Algorithm Validation Program)**: NIST provides a suite of test vectors for block ciphers, including AES, that can be used for validation purposes. You can download them from [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers#test-vectors).
- **OpenSSL**: You can also use OpenSSL to generate reference outputs for verification. This is particularly useful for custom plaintexts or when you want a quick check.

## Summary

To test your AES implementation:

1. Obtain test vectors (key, plaintext, ciphertext) from NIST or another reliable source.
2. Implement a test to ensure your AES function produces the same ciphertext.
3. Automate testing using unit tests for various modes (ECB, CBC, GCM) and key sizes (128, 192, 256 bits).

By using standardized test vectors, you can ensure that your AES implementation is functioning correctly and meets cryptographic standards.
