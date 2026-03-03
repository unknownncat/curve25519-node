use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use wasm_bindgen::prelude::*;
use x25519_dalek::x25519;

fn to_array_32(input: &[u8], label: &str) -> Result<[u8; 32], JsValue> {
    if input.len() != 32 {
        return Err(JsValue::from_str(&format!("{label} must be 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(input);
    Ok(out)
}

fn to_array_64(input: &[u8], label: &str) -> Result<[u8; 64], JsValue> {
    if input.len() != 64 {
        return Err(JsValue::from_str(&format!("{label} must be 64 bytes")));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(input);
    Ok(out)
}

fn x25519_basepoint() -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    base
}

#[wasm_bindgen(js_name = x25519PublicKey)]
pub fn x25519_public_key(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = to_array_32(secret_key, "secret key")?;
    Ok(x25519(secret, x25519_basepoint()).to_vec())
}

#[wasm_bindgen(js_name = x25519SharedKey)]
pub fn x25519_shared_key(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = to_array_32(secret_key, "secret key")?;
    let public = to_array_32(public_key, "public key")?;
    Ok(x25519(secret, public).to_vec())
}

#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(secret_seed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let seed = to_array_32(secret_seed, "secret seed")?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(sk.verifying_key().to_bytes().to_vec())
}

#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(secret_seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let seed = to_array_32(secret_seed, "secret seed")?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(sk.sign(msg).to_bytes().to_vec())
}

#[wasm_bindgen(js_name = ed25519Verify)]
pub fn ed25519_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let pk = to_array_32(public_key, "public key")?;
    let sig = to_array_64(signature, "signature")?;
    let verifying_key = VerifyingKey::from_bytes(&pk)
        .map_err(|_| JsValue::from_str("invalid Ed25519 public key encoding"))?;
    let signature = Signature::from_bytes(&sig);
    Ok(verifying_key.verify(msg, &signature).is_ok())
}
