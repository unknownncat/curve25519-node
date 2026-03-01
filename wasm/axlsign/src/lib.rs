use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};
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

fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
    scalar
}

fn x25519_basepoint() -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    base
}

fn ed_public_from_clamped_secret(clamped_secret: [u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(clamped_secret);
    let point = EdwardsPoint::mul_base(&scalar);
    point.compress().to_bytes()
}

fn sign_internal(secret_key: [u8; 32], msg: &[u8], opt_rnd: Option<[u8; 64]>) -> [u8; 64] {
    let clamped = clamp_scalar(secret_key);
    let a_scalar = Scalar::from_bytes_mod_order(clamped);

    let ed_public = ed_public_from_clamped_secret(clamped);
    let sign_bit = ed_public[31] & 0x80;

    let mut r_hasher = Sha512::new();
    match opt_rnd {
        Some(rnd) => {
            let mut sep = [0xffu8; 32];
            sep[0] = 0xfe;
            r_hasher.update(sep);
            r_hasher.update(clamped);
            r_hasher.update(msg);
            r_hasher.update(rnd);
        }
        None => {
            r_hasher.update(clamped);
            r_hasher.update(msg);
        }
    }

    let r_hash = r_hasher.finalize();
    let mut r_wide = [0u8; 64];
    r_wide.copy_from_slice(&r_hash);
    let r_scalar = Scalar::from_bytes_mod_order_wide(&r_wide);

    let r_point = EdwardsPoint::mul_base(&r_scalar);
    let r_compressed = r_point.compress().to_bytes();

    let mut h_hasher = Sha512::new();
    h_hasher.update(r_compressed);
    h_hasher.update(ed_public);
    h_hasher.update(msg);

    let h_hash = h_hasher.finalize();
    let mut h_wide = [0u8; 64];
    h_wide.copy_from_slice(&h_hash);
    let h_scalar = Scalar::from_bytes_mod_order_wide(&h_wide);

    let s_scalar = r_scalar + h_scalar * a_scalar;

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_compressed);
    signature[32..].copy_from_slice(&s_scalar.to_bytes());
    signature[63] |= sign_bit;
    signature
}

fn verify_internal(public_key: [u8; 32], msg: &[u8], signature: [u8; 64]) -> bool {
    let sign_bit = (signature[63] >> 7) & 1;

    let mut normalized_signature = signature;
    normalized_signature[63] &= 0x7f;

    let montgomery = MontgomeryPoint(public_key);
    let Some(edwards_point) = montgomery.to_edwards(sign_bit) else {
        return false;
    };

    let ed_public = edwards_point.compress().to_bytes();

    let Ok(verifying_key) = VerifyingKey::from_bytes(&ed_public) else {
        return false;
    };

    let signature_obj = Signature::from_bytes(&normalized_signature);
    verifying_key.verify(msg, &signature_obj).is_ok()
}

#[wasm_bindgen(js_name = axlsignPublicKey)]
pub fn axlsign_public_key(secret_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = to_array_32(secret_key, "secret key")?;
    let clamped = clamp_scalar(secret);
    let mut public = x25519(clamped, x25519_basepoint());
    public[31] &= 0x7f;
    Ok(public.to_vec())
}

#[wasm_bindgen(js_name = axlsignSharedKey)]
pub fn axlsign_shared_key(secret_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = to_array_32(secret_key, "secret key")?;
    let public = to_array_32(public_key, "public key")?;
    let shared = x25519(secret, public);
    Ok(shared.to_vec())
}

#[wasm_bindgen(js_name = axlsignSign)]
pub fn axlsign_sign(secret_key: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = to_array_32(secret_key, "secret key")?;
    let signature = sign_internal(secret, msg, None);
    Ok(signature.to_vec())
}

#[wasm_bindgen(js_name = axlsignSignRnd)]
pub fn axlsign_sign_rnd(secret_key: &[u8], msg: &[u8], rnd: &[u8]) -> Result<Vec<u8>, JsValue> {
    let secret = to_array_32(secret_key, "secret key")?;
    let random = to_array_64(rnd, "random")?;
    let signature = sign_internal(secret, msg, Some(random));
    Ok(signature.to_vec())
}

#[wasm_bindgen(js_name = axlsignVerify)]
pub fn axlsign_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let public = to_array_32(public_key, "public key")?;
    let sig = to_array_64(signature, "signature")?;
    Ok(verify_internal(public, msg, sig))
}
