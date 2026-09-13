use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::{rngs::OsRng as RandOsRng, RngCore};
use std::{fs, path::Path};

const SALT_LEN: usize = 16;

/// Derives an AES-256 key from password and salt using Argon2
fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(salt).unwrap();

    let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap();
    let hash_str = hash.hash.unwrap(); // guarda o temporário
    let hash_bytes = hash_str.as_bytes(); // pega os bytes seguros

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[..32]);
    key
}

// https://docs.rs/argon2/latest/argon2/

/// Criptografa um arquivo usando AES-256-GCM + Argon2
pub fn encrypt_file(path: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(path)?;

    let mut salt = [0u8; SALT_LEN];
    RandOsRng.fill_bytes(&mut salt);

    let key_bytes = derive_key_from_password(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| "Chave inválida")?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted = cipher
        .encrypt(&nonce, data.as_ref())
        .map_err(|e| format!("Encryption error: {}", e))?;

    let mut final_data = Vec::new();
    final_data.extend_from_slice(&salt);
    final_data.extend_from_slice(&nonce);
    final_data.extend_from_slice(&encrypted);

    let new_path = path.with_extension("enc");
    fs::write(&new_path, final_data)?;
    println!("Arquivo criptografado salvo em: {:?}", new_path);

    Ok(())
}

/// Descriptografa um arquivo criptografado
pub fn decrypt_file(path: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    if data.len() < SALT_LEN + 12 {
        return Err("Error: File corrupted or too small.".into());
    }

    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce_slice, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    let key_bytes = derive_key_from_password(password, salt);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| "Chave inválida")?;

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption error: {}", e))?;

    let new_path = path.with_extension("dec");
    fs::write(&new_path, decrypted)?;
    println!("Arquivo descriptografado salvo em: {:?}", new_path);

    Ok(())
}

/// Derives master key combining password + USB key
pub fn derive_master_key(
    password: &str,
    usb_key_bytes: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let mut combined = Vec::new();
    combined.extend_from_slice(password.as_bytes());
    combined.extend_from_slice(usb_key_bytes);

    let salt_bytes = b"Nuk4sd_Salt_v0.9_2026";
    let salt = SaltString::encode_b64(salt_bytes).unwrap();

    let argon2 = Argon2::default();
    let hash = argon2.hash_password(&combined, &salt).unwrap();

    let hash_str = hash.hash.unwrap(); // mantém o temporário vivo
    let hash_bytes = hash_str.as_bytes();

    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(&hash_bytes[..32]);

    Ok(master_key)
}

/// Generates a random phrase with a 12-digit random number, hashes it with Argon2, and saves the hash.
/// Returns the plaintext phrase so the user can write it down.
pub fn generate_mac_secret() -> Result<String, Box<dyn std::error::Error>> {
    // Generate a 12-digit random number
    let mut random_bytes = [0u8; 8];
    RandOsRng.fill_bytes(&mut random_bytes);
    let rand_num = u64::from_le_bytes(random_bytes) % 1_000_000_000_000;
    
    // Create the secret phrase without spaces
    let phrase = format!("Nuk4sdRecovery{:012}", rand_num);

    let salt = SaltString::generate(&mut RandOsRng);
    let argon2 = Argon2::default();
    
    // Hash the phrase using Argon2
    let hash = argon2.hash_password(phrase.as_bytes(), &salt)
        .map_err(|e| format!("Argon2 hash failed: {}", e))?;
    let hash_string = hash.to_string(); // PHC string format (contains salt and hash)

    // Save the hash to the home directory
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let secret_path = Path::new(&home_dir).join(".nuk4sd_mac_secret");
    
    fs::write(&secret_path, hash_string)?;
    
    // Set restrictive permissions (600) on Linux
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&secret_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&secret_path, perms);
        }
    }

    Ok(phrase)
}

/// Validates the provided phrase against the stored Argon2 hash.
pub fn validate_mac_secret(phrase: &str) -> bool {
    let home_dir = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let secret_path = Path::new(&home_dir).join(".nuk4sd_mac_secret");
    
    let hash_string = match fs::read_to_string(&secret_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return false,
    };

    let parsed_hash = match argon2::PasswordHash::new(&hash_string) {
        Ok(h) => h,
        Err(_) => return false,
    };

    let argon2 = Argon2::default();
    use argon2::PasswordVerifier;
    
    argon2.verify_password(phrase.as_bytes(), &parsed_hash).is_ok()
}
