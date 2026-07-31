//! End-to-end round-trip tests for every command path (except interactive keymake password).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn bin() -> PathBuf {
    // Prefer release if present, else debug from cargo test env.
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    let release = p.join("release").join(if cfg!(windows) {
        "encrypt.exe"
    } else {
        "encrypt"
    });
    if release.exists() {
        return release;
    }
    p.push("debug");
    p.push(if cfg!(windows) {
        "encrypt.exe"
    } else {
        "encrypt"
    });
    p
}

fn temp_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("encrypt_test_{}_{}", std::process::id(), n));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_file(path: &Path, data: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(data).unwrap();
}

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("spawn encrypt")
}

fn assert_ok(out: &std::process::Output, label: &str) {
    if !out.status.success() {
        panic!(
            "{label} failed\nstatus: {:?}\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn assert_fail(out: &std::process::Output, label: &str) {
    if out.status.success() {
        panic!(
            "{label} unexpectedly succeeded\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn otp_roundtrip_and_guards() {
    let dir = temp_dir();
    let plain = "hello OTP world".as_bytes();
    write_file(&dir.join("in.bin"), plain);
    // key longer than input
    write_file(&dir.join("key.key"), &[0xA5u8; 64]);

    let out = run_in(&dir, &["otp", "in.bin", "enc.bin"]);
    assert_ok(&out, "otp encrypt");
    let enc = fs::read(dir.join("enc.bin")).unwrap();
    assert_ne!(enc, plain);

    let out = run_in(&dir, &["otp", "enc.bin", "out.bin"]);
    assert_ok(&out, "otp decrypt");
    assert_eq!(fs::read(dir.join("out.bin")).unwrap(), plain);

    // refuse overwrite
    let out = run_in(&dir, &["otp", "in.bin", "out.bin"]);
    assert_fail(&out, "otp overwrite");

    // key too short
    write_file(&dir.join("key.key"), b"short");
    write_file(&dir.join("big.in"), &[1u8; 32]);
    let out = run_in(&dir, &["otp", "big.in", "should_fail.bin"]);
    assert_fail(&out, "otp short key");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn aes_roundtrip() {
    let dir = temp_dir();
    let plain: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    write_file(&dir.join("plain.bin"), &plain);
    write_file(&dir.join("aes.key"), &[0x11u8; 32]);

    let out = run_in(&dir, &["aes", "plain.bin", "cipher.bin"]);
    assert_ok(&out, "aes encrypt");
    assert_ne!(fs::read(dir.join("cipher.bin")).unwrap(), plain);

    let out = run_in(&dir, &["aes", "cipher.bin", "plain2.bin"]);
    assert_ok(&out, "aes decrypt");
    assert_eq!(fs::read(dir.join("plain2.bin")).unwrap(), plain);

    // wrong key → auth fail
    write_file(&dir.join("aes.key"), &[0x22u8; 32]);
    let out = run_in(&dir, &["aes", "cipher.bin", "bad.bin"]);
    assert_fail(&out, "aes wrong key");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn xcha_roundtrip() {
    let dir = temp_dir();
    let plain = b"xchacha payload with unicode pi~3.14";
    write_file(&dir.join("plain.bin"), plain);
    write_file(&dir.join("key.key"), &[0x33u8; 32]);

    assert_ok(
        &run_in(&dir, &["xcha", "plain.bin", "c.bin"]),
        "xcha enc",
    );
    assert_ok(&run_in(&dir, &["xcha", "c.bin", "p2.bin"]), "xcha dec");
    assert_eq!(fs::read(dir.join("p2.bin")).unwrap(), plain);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ser_roundtrip() {
    let dir = temp_dir();
    let plain: Vec<u8> = (0..50_000u32).map(|i| (i.wrapping_mul(7) % 256) as u8).collect();
    write_file(&dir.join("plain.bin"), &plain);
    write_file(&dir.join("key.key"), &[0x44u8; 32]);

    assert_ok(&run_in(&dir, &["ser", "plain.bin", "c.bin"]), "ser enc");
    assert_ok(&run_in(&dir, &["ser", "c.bin", "p2.bin"]), "ser dec");
    assert_eq!(fs::read(dir.join("p2.bin")).unwrap(), plain);

    // wrong key
    write_file(&dir.join("key.key"), &[0x55u8; 32]);
    assert_fail(&run_in(&dir, &["ser", "c.bin", "bad.bin"]), "ser wrong key");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tf_roundtrip() {
    let dir = temp_dir();
    let plain = b"threefish-1024 test vector content!!!";
    write_file(&dir.join("plain.bin"), plain);
    write_file(&dir.join("key.key"), &[0x66u8; 128]);

    assert_ok(&run_in(&dir, &["tf", "plain.bin", "c.bin"]), "tf enc");
    assert_ok(&run_in(&dir, &["tf", "c.bin", "p2.bin"]), "tf dec");
    assert_eq!(fs::read(dir.join("p2.bin")).unwrap(), plain);

    // key too short
    write_file(&dir.join("key.key"), &[0x66u8; 64]);
    assert_fail(
        &run_in(&dir, &["tf", "plain.bin", "fail.bin"]),
        "tf short key",
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn empty_file_aead() {
    let dir = temp_dir();
    write_file(&dir.join("empty"), b"");
    write_file(&dir.join("aes.key"), &[0x77u8; 32]);
    assert_ok(&run_in(&dir, &["aes", "empty", "e.enc"]), "empty enc");
    assert_ok(&run_in(&dir, &["aes", "e.enc", "e.out"]), "empty dec");
    assert_eq!(fs::read(dir.join("e.out")).unwrap(), b"");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn keymake_refuse_overwrite_and_size_validation() {
    let dir = temp_dir();
    write_file(&dir.join("key.key"), b"exists");

    // size 0 invalid
    let out = Command::new(bin())
        .current_dir(&dir)
        .args(["keymake", "0"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_fail(&out, "keymake size 0");

    // refuse overwrite without even prompting successfully for long
    let out = Command::new(bin())
        .current_dir(&dir)
        .args(["keymake", "32"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_fail(&out, "keymake overwrite");
    // key still original
    assert_eq!(fs::read(dir.join("key.key")).unwrap(), b"exists");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn multi_megabyte_stream() {
    let dir = temp_dir();
    // > 1 MiB to force multiple chunks
    let plain: Vec<u8> = (0..3_000_000u32).map(|i| (i % 256) as u8).collect();
    write_file(&dir.join("plain.bin"), &plain);
    write_file(&dir.join("key.key"), &[0x88u8; 32]);

    assert_ok(
        &run_in(&dir, &["xcha", "plain.bin", "c.bin"]),
        "xcha big enc",
    );
    assert_ok(&run_in(&dir, &["xcha", "c.bin", "p2.bin"]), "xcha big dec");
    assert_eq!(fs::read(dir.join("p2.bin")).unwrap(), plain);

    let _ = fs::remove_dir_all(&dir);
}
