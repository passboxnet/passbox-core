//! Streaming encryption of file attachments.
//!
//! Every attachment has its own random 256-bit `file_key`. The key, the file
//! name, its media type and size are stored inside the encrypted item, so
//! they are protected by the vault key like the rest of the item; the
//! server only stores the encrypted blob.
//!
//! The blob follows the STREAM construction (Hoang, Reyhanitabar, Rogaway,
//! Vizár, "Online Authenticated-Encryption and its Nonce-Reuse
//! Misuse-Resistance"): the file is split into chunks of `chunk_size`
//! bytes (1 MiB), each sealed with XChaCha20-Poly1305 under `file_key`.
//!
//! ```text
//! blob   = header (24 B) || chunk_0 || chunk_1 || ... || chunk_n
//! header = "PBXF" || version (1) || chunk_size (u32 BE) || nonce_prefix (15 B, random)
//! nonce  = nonce_prefix || index (u64 BE) || last (0x00 or 0x01)
//! aad    = "passbox/v1/file|{file_id}|{index}|{last}" || 0x00 || header
//! chunk  = XChaCha20-Poly1305(file_key, nonce, plaintext_i, aad)   (len + 16 B tag)
//! ```
//!
//! Every chunk but the last has exactly `chunk_size` plaintext bytes; the
//! last has at most `chunk_size` (an empty file is one empty last chunk).
//! Because the index and the "last" flag are authenticated, chunks cannot
//! be reordered, dropped, duplicated or cut off at a chunk boundary without
//! decryption failing; the header (chunk size, nonce prefix) is
//! authenticated by every chunk. The file ID binds the blob to its
//! attachment: the server cannot hand out one attachment's blob for
//! another (and a blob would not decrypt under another file's key anyway).
//! The item ID is deliberately not bound, so an item can move between
//! vaults without re-encrypting its files.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::aead::SymmetricKey;
use crate::{Error, Result, encoding, random};

/// Magic bytes at the start of every encrypted file.
pub const MAGIC: &[u8; 4] = b"PBXF";
/// File format version.
pub const VERSION: u8 = 1;
/// Length of the header in bytes.
pub const HEADER_LEN: usize = 24;
/// Plaintext bytes per chunk written by this version.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Authentication tag per chunk.
pub const TAG_LEN: usize = 16;
const PREFIX_LEN: usize = 15;
const MIN_CHUNK_SIZE: usize = 1024;
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Generates a new random file key, Base64url-encoded (to store in the item).
pub fn generate_key() -> Result<String> {
    Ok(encoding::encode(SymmetricKey::generate()?.as_bytes()))
}

/// Parses a Base64url file key.
pub fn parse_key(key: &str) -> Result<SymmetricKey> {
    let bytes = encoding::decode(key)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::InvalidData("a file key has 32 bytes".into()))?;
    Ok(SymmetricKey::from_bytes(bytes))
}

/// Size of the encrypted blob for a file of `plain_len` bytes.
pub fn encrypted_len(plain_len: u64) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    let chunks = if plain_len == 0 {
        1
    } else {
        plain_len.div_ceil(chunk)
    };
    HEADER_LEN as u64 + plain_len + chunks * TAG_LEN as u64
}

fn chunk_aad(file_id: &str, index: u64, last: bool, header: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut aad = format!("passbox/v1/file|{file_id}|{index}|{}", u8::from(last)).into_bytes();
    aad.push(0);
    aad.extend_from_slice(header);
    aad
}

fn chunk_nonce(header: &[u8; HEADER_LEN], index: u64, last: bool) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..PREFIX_LEN].copy_from_slice(&header[HEADER_LEN - PREFIX_LEN..]);
    nonce[PREFIX_LEN..PREFIX_LEN + 8].copy_from_slice(&index.to_be_bytes());
    nonce[23] = u8::from(last);
    XNonce::from(nonce)
}

fn check_file_id(file_id: &str) -> Result<()> {
    if file_id.is_empty() || file_id.len() > 64 || file_id.contains('|') {
        return Err(Error::InvalidData("invalid file id".into()));
    }
    Ok(())
}

/// Encrypts a file chunk by chunk.
pub struct FileEncryptor {
    cipher: XChaCha20Poly1305,
    file_id: String,
    header: [u8; HEADER_LEN],
    index: u64,
    finished: bool,
}

impl FileEncryptor {
    /// Starts a new blob with a random nonce prefix and [`CHUNK_SIZE`].
    pub fn new(key: &SymmetricKey, file_id: &str) -> Result<Self> {
        check_file_id(file_id)?;
        let prefix: [u8; PREFIX_LEN] = random::bytes()?;
        let mut header = [0u8; HEADER_LEN];
        header[..4].copy_from_slice(MAGIC);
        header[4] = VERSION;
        header[5..9].copy_from_slice(&(CHUNK_SIZE as u32).to_be_bytes());
        header[9..].copy_from_slice(&prefix);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&(*key.as_bytes()).into()),
            file_id: file_id.to_owned(),
            header,
            index: 0,
            finished: false,
        })
    }

    /// The header; write it before the first chunk.
    pub fn header(&self) -> [u8; HEADER_LEN] {
        self.header
    }

    /// Plaintext bytes per chunk.
    pub fn chunk_size(&self) -> usize {
        CHUNK_SIZE
    }

    /// Encrypts the next chunk. Every chunk but the last must have exactly
    /// [`FileEncryptor::chunk_size`] bytes; the last one may be shorter.
    pub fn encrypt_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::InvalidData("the file is already complete".into()));
        }
        if plaintext.len() > CHUNK_SIZE || (!last && plaintext.len() != CHUNK_SIZE) {
            return Err(Error::InvalidData("wrong chunk length".into()));
        }
        let aad = chunk_aad(&self.file_id, self.index, last, &self.header);
        let ciphertext = self
            .cipher
            .encrypt(
                &chunk_nonce(&self.header, self.index, last),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Decryption)?;
        self.index += 1;
        self.finished = last;
        Ok(ciphertext)
    }
}

/// Decrypts a blob chunk by chunk.
pub struct FileDecryptor {
    cipher: XChaCha20Poly1305,
    file_id: String,
    header: [u8; HEADER_LEN],
    chunk_size: usize,
    index: u64,
    finished: bool,
}

impl FileDecryptor {
    /// Reads the header (the first [`HEADER_LEN`] bytes of the blob).
    pub fn new(key: &SymmetricKey, file_id: &str, header: &[u8]) -> Result<Self> {
        check_file_id(file_id)?;
        let header: [u8; HEADER_LEN] = header.try_into().map_err(|_| Error::MalformedEnvelope)?;
        if &header[..4] != MAGIC {
            return Err(Error::MalformedEnvelope);
        }
        if header[4] != VERSION {
            return Err(Error::UnsupportedEnvelope);
        }
        let chunk_size = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::MalformedEnvelope);
        }
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&(*key.as_bytes()).into()),
            file_id: file_id.to_owned(),
            header,
            chunk_size,
            index: 0,
            finished: false,
        })
    }

    /// Plaintext bytes per chunk.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Bytes per encrypted chunk (all but the last chunk have this size).
    pub fn encrypted_chunk_size(&self) -> usize {
        self.chunk_size + TAG_LEN
    }

    /// Decrypts the next chunk; `last` must be set for the final one.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8], last: bool) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::Decryption);
        }
        if ciphertext.len() < TAG_LEN
            || ciphertext.len() > self.encrypted_chunk_size()
            || (!last && ciphertext.len() != self.encrypted_chunk_size())
        {
            return Err(Error::Decryption);
        }
        let aad = chunk_aad(&self.file_id, self.index, last, &self.header);
        let plaintext = self
            .cipher
            .decrypt(
                &chunk_nonce(&self.header, self.index, last),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Decryption)?;
        self.index += 1;
        self.finished = last;
        Ok(plaintext)
    }

    /// Fails unless the last chunk was decrypted (catches truncated blobs).
    pub fn finish(&self) -> Result<()> {
        if self.finished {
            Ok(())
        } else {
            Err(Error::Decryption)
        }
    }
}

/// Encrypts a whole file in memory.
pub fn encrypt_file(key: &SymmetricKey, file_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut encryptor = FileEncryptor::new(key, file_id)?;
    let mut out = Vec::with_capacity(encrypted_len(data.len() as u64) as usize);
    out.extend_from_slice(&encryptor.header());
    if data.is_empty() {
        out.extend(encryptor.encrypt_chunk(&[], true)?);
        return Ok(out);
    }
    let mut chunks = data.chunks(CHUNK_SIZE).peekable();
    while let Some(chunk) = chunks.next() {
        let last = chunks.peek().is_none();
        out.extend(encryptor.encrypt_chunk(chunk, last)?);
    }
    Ok(out)
}

/// Decrypts a whole blob in memory.
pub fn decrypt_file(key: &SymmetricKey, file_id: &str, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::MalformedEnvelope);
    }
    let (header, mut rest) = blob.split_at(HEADER_LEN);
    let mut decryptor = FileDecryptor::new(key, file_id, header)?;
    let size = decryptor.encrypted_chunk_size();
    let mut out = Vec::with_capacity(rest.len());
    loop {
        let last = rest.len() <= size;
        let take = rest.len().min(size);
        let (chunk, tail) = rest.split_at(take);
        out.extend(decryptor.decrypt_chunk(chunk, last)?);
        rest = tail;
        if last {
            break;
        }
    }
    decryptor.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SymmetricKey {
        SymmetricKey::from_bytes([7; 32])
    }

    #[test]
    fn round_trips_all_sizes() {
        for len in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE + 5,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let blob = encrypt_file(&key(), "f1", &data).unwrap();
            assert_eq!(blob.len() as u64, encrypted_len(len as u64), "len {len}");
            assert_eq!(
                decrypt_file(&key(), "f1", &blob).unwrap(),
                data,
                "len {len}"
            );
        }
    }

    #[test]
    fn streaming_matches_whole_file() {
        let data = vec![3u8; CHUNK_SIZE + 10];
        let mut enc = FileEncryptor::new(&key(), "f1").unwrap();
        let mut blob = enc.header().to_vec();
        blob.extend(enc.encrypt_chunk(&data[..CHUNK_SIZE], false).unwrap());
        blob.extend(enc.encrypt_chunk(&data[CHUNK_SIZE..], true).unwrap());
        assert!(enc.encrypt_chunk(&[], true).is_err());
        assert_eq!(decrypt_file(&key(), "f1", &blob).unwrap(), data);

        let mut dec = FileDecryptor::new(&key(), "f1", &blob[..HEADER_LEN]).unwrap();
        let first = &blob[HEADER_LEN..HEADER_LEN + dec.encrypted_chunk_size()];
        assert_eq!(dec.decrypt_chunk(first, false).unwrap(), data[..CHUNK_SIZE]);
        assert!(dec.finish().is_err(), "not finished before the last chunk");
    }

    #[test]
    fn rejects_short_middle_chunks() {
        let mut enc = FileEncryptor::new(&key(), "f1").unwrap();
        assert!(enc.encrypt_chunk(&[1, 2, 3], false).is_err());
    }

    #[test]
    fn detects_tampering_truncation_and_swaps() {
        let data = vec![9u8; 2 * CHUNK_SIZE + 3];
        let blob = encrypt_file(&key(), "f1", &data).unwrap();
        // Wrong key and wrong file ID.
        assert!(decrypt_file(&SymmetricKey::from_bytes([8; 32]), "f1", &blob).is_err());
        assert!(decrypt_file(&key(), "f2", &blob).is_err());
        // Flipped bit in a chunk and in the header.
        let mut bad = blob.clone();
        bad[HEADER_LEN + 10] ^= 1;
        assert!(decrypt_file(&key(), "f1", &bad).is_err());
        let mut bad = blob.clone();
        bad[20] ^= 1;
        assert!(decrypt_file(&key(), "f1", &bad).is_err());
        // Cut off after the first chunk: that chunk is not marked last.
        let cut = HEADER_LEN + CHUNK_SIZE + TAG_LEN;
        assert!(decrypt_file(&key(), "f1", &blob[..cut]).is_err());
        // Chunks swapped.
        let c = CHUNK_SIZE + TAG_LEN;
        let mut swapped = blob[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&blob[HEADER_LEN + c..HEADER_LEN + 2 * c]);
        swapped.extend_from_slice(&blob[HEADER_LEN..HEADER_LEN + c]);
        swapped.extend_from_slice(&blob[HEADER_LEN + 2 * c..]);
        assert!(decrypt_file(&key(), "f1", &swapped).is_err());
        // Extra bytes after the end.
        let mut long = blob.clone();
        long.extend_from_slice(&[0; 20]);
        assert!(decrypt_file(&key(), "f1", &long).is_err());
    }

    #[test]
    fn header_checks() {
        let blob = encrypt_file(&key(), "f1", b"hello").unwrap();
        let mut bad = blob.clone();
        bad[0] = b'X';
        assert_eq!(
            decrypt_file(&key(), "f1", &bad).err(),
            Some(Error::MalformedEnvelope)
        );
        let mut bad = blob.clone();
        bad[4] = 2;
        assert_eq!(
            decrypt_file(&key(), "f1", &bad).err(),
            Some(Error::UnsupportedEnvelope)
        );
        assert!(FileEncryptor::new(&key(), "a|b").is_err());
    }

    #[test]
    fn keys_round_trip() {
        let key = generate_key().unwrap();
        assert_eq!(encoding::encode(parse_key(&key).unwrap().as_bytes()), key);
        assert!(parse_key("AAAA").is_err());
    }
}
