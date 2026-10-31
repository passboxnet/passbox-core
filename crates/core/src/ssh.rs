//! SSH keys for the "SSH key" item type: Ed25519 key generation in
//! the OpenSSH formats, public keys and fingerprints.
//!
//! Private keys are written in the unencrypted `openssh-key-v1` format
//! (what `ssh-keygen -t ed25519 -N ""` writes); they are protected by the
//! vault like every other item field. Only Ed25519 keys are generated;
//! other key types can be stored as text, and their public key line is
//! shown as it was entered.

use data_encoding::{BASE64, BASE64_NOPAD};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result, random};

const KEY_TYPE: &str = "ssh-ed25519";
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// A new key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeyPair {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` …
    pub private_key: String,
    /// `ssh-ed25519 AAAA… comment`, for `authorized_keys`.
    pub public_key: String,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, public);
    blob
}

fn fingerprint_of_blob(blob: &[u8]) -> String {
    format!("SHA256:{}", BASE64_NOPAD.encode(&Sha256::digest(blob)))
}

fn clean_comment(comment: &str) -> String {
    comment
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_owned()
}

fn public_line(public: &[u8; 32], comment: &str) -> String {
    let encoded = BASE64.encode(&public_blob(public));
    if comment.is_empty() {
        format!("{KEY_TYPE} {encoded}")
    } else {
        format!("{KEY_TYPE} {encoded} {comment}")
    }
}

fn private_pem(seed: &[u8; 32], public: &[u8; 32], comment: &str) -> Result<String> {
    let check: [u8; 4] = random::bytes()?;
    let mut private = Zeroizing::new(Vec::with_capacity(160));
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    put_string(&mut private, KEY_TYPE.as_bytes());
    put_string(&mut private, public);
    let mut secret = Zeroizing::new([0u8; 64]);
    secret[..32].copy_from_slice(seed);
    secret[32..].copy_from_slice(public);
    put_string(&mut private, secret.as_ref());
    put_string(&mut private, comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }

    let mut out = Zeroizing::new(Vec::with_capacity(320));
    out.extend_from_slice(AUTH_MAGIC);
    put_string(&mut out, b"none");
    put_string(&mut out, b"none");
    put_string(&mut out, b"");
    out.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut out, &public_blob(public));
    put_string(&mut out, &private);

    let encoded = Zeroizing::new(BASE64.encode(&out));
    let mut pem = String::with_capacity(encoded.len() + 80);
    pem.push_str(PEM_BEGIN);
    pem.push('\n');
    for line in encoded.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(line).map_err(|_| Error::InvalidEncoding)?);
        pem.push('\n');
    }
    pem.push_str(PEM_END);
    pem.push('\n');
    Ok(pem)
}

/// Generates a new Ed25519 key pair. `comment` usually is `user@host` or
/// what the key is for; control characters are removed.
pub fn generate_ed25519(comment: &str) -> Result<SshKeyPair> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(random::bytes()?);
    let key = SigningKey::from_bytes(&seed);
    let public = key.verifying_key().to_bytes();
    let comment = clean_comment(comment);
    Ok(SshKeyPair {
        private_key: private_pem(&seed, &public, &comment)?,
        public_key: public_line(&public, &comment),
        fingerprint: fingerprint_of_blob(&public_blob(&public)),
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::InvalidData("truncated SSH key".into()));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// The public key line and fingerprint of an unencrypted OpenSSH Ed25519
/// private key (as written by [`generate_ed25519`] or `ssh-keygen`).
/// Fails for other key types and for passphrase-protected keys.
pub fn public_key_of(private_key: &str) -> Result<(String, String)> {
    let body: String = private_key
        .trim()
        .strip_prefix(PEM_BEGIN)
        .and_then(|rest| rest.trim_end().strip_suffix(PEM_END))
        .ok_or_else(|| Error::InvalidData("not an OpenSSH private key".into()))?
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let raw = Zeroizing::new(
        BASE64
            .decode(body.as_bytes())
            .map_err(|_| Error::InvalidEncoding)?,
    );
    let mut reader = Reader(&raw);
    if reader.take(AUTH_MAGIC.len())? != AUTH_MAGIC {
        return Err(Error::InvalidData("not an OpenSSH private key".into()));
    }
    let cipher = reader.string()?;
    reader.string()?;
    reader.string()?;
    if cipher != b"none" {
        return Err(Error::InvalidData(
            "the key is protected with a passphrase".into(),
        ));
    }
    if reader.u32()? != 1 {
        return Err(Error::InvalidData("expected exactly one key".into()));
    }
    let mut public = Reader(reader.string()?);
    if public.string()? != KEY_TYPE.as_bytes() {
        return Err(Error::InvalidData("only Ed25519 keys are supported".into()));
    }
    let public: [u8; 32] = public
        .string()?
        .try_into()
        .map_err(|_| Error::InvalidData("invalid Ed25519 public key".into()))?;
    let mut private = Reader(reader.string()?);
    let (a, b) = (private.u32()?, private.u32()?);
    if a != b {
        return Err(Error::InvalidData("corrupt private key".into()));
    }
    if private.string()? != KEY_TYPE.as_bytes() || private.string()? != public {
        return Err(Error::InvalidData("corrupt private key".into()));
    }
    let secret = private.string()?;
    if secret.len() != 64 {
        return Err(Error::InvalidData("corrupt private key".into()));
    }
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        secret[..32]
            .try_into()
            .map_err(|_| Error::InvalidData("corrupt private key".into()))?,
    );
    if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public {
        return Err(Error::InvalidData(
            "the private key does not match its public key".into(),
        ));
    }
    let comment = clean_comment(&String::from_utf8_lossy(private.string()?));
    Ok((
        public_line(&public, &comment),
        fingerprint_of_blob(&public_blob(&public)),
    ))
}

/// The `SHA256:` fingerprint of a public key line (`type base64 [comment]`),
/// for any key type.
pub fn fingerprint(public_key: &str) -> Result<String> {
    let mut parts = public_key.split_whitespace();
    let (Some(_), Some(encoded)) = (parts.next(), parts.next()) else {
        return Err(Error::InvalidData("not an SSH public key".into()));
    };
    let blob = BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| Error::InvalidEncoding)?;
    let mut reader = Reader(&blob);
    let key_type = reader.string()?;
    if !key_type.starts_with(b"ssh-")
        && !key_type.starts_with(b"ecdsa-")
        && !key_type.starts_with(b"sk-")
    {
        return Err(Error::InvalidData("not an SSH public key".into()));
    }
    Ok(fingerprint_of_blob(&blob))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Written by Python `cryptography` (an independent implementation) for
    // the seed 0x00..0x1f, without a comment.
    const OPENSSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACADoQe/884Qvh1w3RjnS8CZZ+TWMJulDV8d3IZkElUxuAAA
AIjwhM7z8ITO8wAAAAtzc2gtZWQyNTUxOQAAACADoQe/884Qvh1w3RjnS8CZZ+TW
MJulDV8d3IZkElUxuAAAAEAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0e
HwOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn generated_keys_parse_back() {
        let pair = generate_ed25519("deploy@example.com\n").unwrap();
        assert!(pair.private_key.starts_with(PEM_BEGIN));
        assert!(
            pair.public_key
                .starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI")
        );
        assert!(pair.public_key.ends_with(" deploy@example.com"));
        assert!(pair.fingerprint.starts_with("SHA256:"));
        assert_eq!(pair.fingerprint.len(), 7 + 43);
        let (public, fp) = public_key_of(&pair.private_key).unwrap();
        assert_eq!(public, pair.public_key);
        assert_eq!(fp, pair.fingerprint);
        assert_eq!(fingerprint(&pair.public_key).unwrap(), pair.fingerprint);
        assert_ne!(
            generate_ed25519("").unwrap().public_key,
            pair.public_key,
            "keys are random"
        );
    }

    #[test]
    fn reads_ssh_keygen_output() {
        let (public, fp) = public_key_of(OPENSSH_KEY).unwrap();
        assert_eq!(
            public,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"
        );
        assert_eq!(fp, "SHA256:lbmsoA0yIEcEiVDRnMWuzm+nV+3ZEEpVIURqFoeSspg");
        assert_eq!(fingerprint(&public).unwrap(), fp);
    }

    #[test]
    fn rejects_garbage() {
        assert!(public_key_of("hello").is_err());
        assert!(public_key_of(&OPENSSH_KEY.replace("b3Bl", "c3Bl")).is_err());
        assert!(fingerprint("ssh-ed25519").is_err());
        assert!(fingerprint("ssh-ed25519 !!!").is_err());
    }
}
