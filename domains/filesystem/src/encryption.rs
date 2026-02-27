use crate::error::{ClawFSError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::STANDARD};

const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;
const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_SIZE: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub secret_id: String,
    pub encrypted_value: String,
    pub iv: String,
    pub auth_tag: String,
    pub algorithm: String,
    pub key_id: String,
    pub kdf: KdfParams,
    pub created_at: String,
    pub updated_at: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
}

pub struct SecretEncryptor {
    master_key: [u8; KEY_SIZE],
}

impl SecretEncryptor {
    pub fn new(master_key: [u8; KEY_SIZE]) -> Self {
        Self { master_key }
    }

    pub fn generate_master_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    pub fn derive_secret_key(&self, secret_id: &str, version: u32) -> [u8; KEY_SIZE] {
        let salt = format!("{}:v{}", secret_id, version);
        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(
            self.master_key.as_ref(),
            salt.as_bytes(),
            PBKDF2_ITERATIONS,
            &mut key,
        );
        key
    }

    pub fn encrypt(&self, secret_id: &str, plaintext: &[u8]) -> Result<SecretMetadata> {
        let version = 1;
        let key = self.derive_secret_key(secret_id, version);
        let cipher = Aes256Gcm::new(&key.into());

        let mut nonce_bytes = [0u8; IV_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| ClawFSError::Encryption(e.to_string()))?;

        let auth_tag_offset = ciphertext.len() - AUTH_TAG_SIZE;
        let ciphertext_bytes = &ciphertext[..auth_tag_offset];
        let auth_tag_bytes = &ciphertext[auth_tag_offset..];

        let now = chrono::Utc::now().to_rfc3339();

        Ok(SecretMetadata {
            secret_id: secret_id.to_string(),
            encrypted_value: STANDARD.encode(ciphertext_bytes),
            iv: STANDARD.encode(nonce_bytes),
            auth_tag: STANDARD.encode(auth_tag_bytes),
            algorithm: "AES-256-GCM".to_string(),
            key_id: "kernel-keyring:clawos-master".to_string(),
            kdf: KdfParams {
                algorithm: "PBKDF2-HMAC-SHA256".to_string(),
                iterations: PBKDF2_ITERATIONS,
                salt: STANDARD.encode(format!("{}:v{}", secret_id, version)),
            },
            created_at: now.clone(),
            updated_at: now,
            version,
        })
    }

    pub fn decrypt(&self, metadata: &SecretMetadata) -> Result<Vec<u8>> {
        let key = self.derive_secret_key(&metadata.secret_id, metadata.version);
        let cipher = Aes256Gcm::new(&key.into());

        let mut nonce_bytes = [0u8; IV_SIZE];
        STANDARD.decode_slice(&metadata.iv, &mut nonce_bytes)
            .map_err(|e| ClawFSError::Decryption(format!("Invalid IV: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = STANDARD.decode(&metadata.encrypted_value)
            .map_err(|e| ClawFSError::Decryption(format!("Invalid ciphertext: {}", e)))?;

        let auth_tag = STANDARD.decode(&metadata.auth_tag)
            .map_err(|e| ClawFSError::Decryption(format!("Invalid auth tag: {}", e)))?;

        let mut encrypted = Vec::with_capacity(ciphertext.len() + auth_tag.len());
        encrypted.extend_from_slice(&ciphertext);
        encrypted.extend_from_slice(&auth_tag);

        let plaintext = cipher
            .decrypt(nonce, encrypted.as_ref())
            .map_err(|e| ClawFSError::Decryption(e.to_string()))?;

        Ok(plaintext)
    }

    pub fn rotate_key(&self, old_metadata: &SecretMetadata) -> Result<SecretMetadata> {
        let plaintext = self.decrypt(old_metadata)?;
        let new_version = old_metadata.version + 1;
        let key = self.derive_secret_key(&old_metadata.secret_id, new_version);
        let cipher = Aes256Gcm::new(&key.into());

        let mut nonce_bytes = [0u8; IV_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| ClawFSError::Encryption(e.to_string()))?;

        let auth_tag_offset = ciphertext.len() - AUTH_TAG_SIZE;
        let ciphertext_bytes = &ciphertext[..auth_tag_offset];
        let auth_tag_bytes = &ciphertext[auth_tag_offset..];

        let now = chrono::Utc::now().to_rfc3339();

        Ok(SecretMetadata {
            secret_id: old_metadata.secret_id.clone(),
            encrypted_value: STANDARD.encode(ciphertext_bytes),
            iv: STANDARD.encode(nonce_bytes),
            auth_tag: STANDARD.encode(auth_tag_bytes),
            algorithm: "AES-256-GCM".to_string(),
            key_id: "kernel-keyring:clawos-master".to_string(),
            kdf: KdfParams {
                algorithm: "PBKDF2-HMAC-SHA256".to_string(),
                iterations: PBKDF2_ITERATIONS,
                salt: STANDARD.encode(format!("{}:v{}", old_metadata.secret_id, new_version)),
            },
            created_at: old_metadata.created_at.clone(),
            updated_at: now,
            version: new_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_master_key() {
        let key1 = SecretEncryptor::generate_master_key();
        let key2 = SecretEncryptor::generate_master_key();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_secret_key() {
        let master_key = SecretEncryptor::generate_master_key();
        let encryptor = SecretEncryptor::new(master_key);

        let key1 = encryptor.derive_secret_key("test-secret", 1);
        let key2 = encryptor.derive_secret_key("test-secret", 1);
        let key3 = encryptor.derive_secret_key("test-secret", 2);
        let key4 = encryptor.derive_secret_key("other-secret", 1);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let master_key = SecretEncryptor::generate_master_key();
        let encryptor = SecretEncryptor::new(master_key);

        let plaintext = b"my-secret-api-key-12345";
        let metadata = encryptor.encrypt("test-secret", plaintext).unwrap();

        let decrypted = encryptor.decrypt(&metadata).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_different_keys() {
        let master_key1 = SecretEncryptor::generate_master_key();
        let encryptor1 = SecretEncryptor::new(master_key1);

        let master_key2 = SecretEncryptor::generate_master_key();
        let encryptor2 = SecretEncryptor::new(master_key2);

        let plaintext = b"my-secret-api-key-12345";
        let metadata = encryptor1.encrypt("test-secret", plaintext).unwrap();

        let result = encryptor2.decrypt(&metadata);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_key() {
        let master_key = SecretEncryptor::generate_master_key();
        let encryptor = SecretEncryptor::new(master_key);

        let plaintext = b"my-secret-api-key-12345";
        let metadata1 = encryptor.encrypt("test-secret", plaintext).unwrap();
        assert_eq!(metadata1.version, 1);

        let metadata2 = encryptor.rotate_key(&metadata1).unwrap();
        assert_eq!(metadata2.version, 2);

        let decrypted1 = encryptor.decrypt(&metadata1).unwrap();
        let decrypted2 = encryptor.decrypt(&metadata2).unwrap();
        assert_eq!(plaintext, decrypted1.as_slice());
        assert_eq!(plaintext, decrypted2.as_slice());
    }
}
