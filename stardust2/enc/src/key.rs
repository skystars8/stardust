// IMPORTANT: This key is the only way to decrypt files produced by this build.
//
// Keep a secure backup of this source file before encrypting anything important.
// Changing even one byte makes every existing encrypted file unrecoverable.
//
// A key embedded in a program can be extracted by somebody who obtains the
// executable. This design is convenient, but it does not protect data from an
// attacker who has the program.
pub(crate) const KEY: [u8; 32] = [
    0xa6, 0x89, 0x32, 0x24, 0xf9, 0xb4, 0x4a, 0xfb, 0x1c, 0x7b, 0x28, 0x09, 0x52, 0x6d, 0x87, 0x32,
    0xa0, 0x0c, 0xcf, 0xb5, 0xca, 0x8f, 0xae, 0x36, 0x91, 0x3a, 0x65, 0x93, 0xb4, 0x4d, 0x6d, 0x91,
];
