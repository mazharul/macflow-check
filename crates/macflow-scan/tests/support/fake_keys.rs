//! Fake private-key files for tests, built at runtime.
//!
//! No key-shaped literal lives in the source, so secret scanners (GitGuardian,
//! GitHub secret scanning) have nothing to flag. The bodies are filler bytes:
//! they carry only the headers the scanner reads, never a usable key.
#![allow(dead_code)]

// Split so the source never contains a full key header.
const PRIVATE_KEY: &str = concat!("PRIV", "ATE KEY");

/// An OpenSSH-format key with the given cipher and KDF names and a filler body.
/// `("none", "none")` is what the scanner treats as unencrypted.
pub fn openssh(cipher: &str, kdf: &str) -> String {
    fn put_str(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }
    let mut public = Vec::new();
    put_str(&mut public, b"ssh-ed25519");
    put_str(&mut public, &[0u8; 32]);

    let mut bytes = b"openssh-key-v1\0".to_vec();
    put_str(&mut bytes, cipher.as_bytes());
    put_str(&mut bytes, kdf.as_bytes());
    put_str(&mut bytes, b"");
    bytes.extend_from_slice(&1u32.to_be_bytes());
    put_str(&mut bytes, &public);
    put_str(&mut bytes, b"FAKE-TEST-KEY-NOT-A-SECRET");
    pem("OPENSSH ", &[], &base64(&bytes))
}

/// A PEM block such as `RSA ` or `ENCRYPTED ` (label includes its trailing
/// space; empty for PKCS#8), with optional header lines and a filler body.
pub fn pem(label: &str, headers: &[&str], body: &str) -> String {
    let mut out = format!("-----BEGIN {label}{PRIVATE_KEY}-----\n");
    for h in headers {
        out.push_str(h);
        out.push('\n');
    }
    if !headers.is_empty() {
        out.push('\n');
    }
    for chunk in body.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}{PRIVATE_KEY}-----\n"));
    out
}

/// Obvious filler for PEM bodies the scanner never decodes.
pub const FILLER: &str = "FAKEKEYFORTESTSONLYxNOTxAxSECRETxFAKEKEYFORTESTSONLY";

fn base64(data: &[u8]) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
