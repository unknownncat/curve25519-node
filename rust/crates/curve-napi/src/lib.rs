use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use napi::bindgen_prelude::Buffer;
use napi::Error;
use napi::Result;
use napi_derive::napi;
use sha2::{Digest, Sha512};
use x25519_dalek::x25519;

fn to_array_32(input: &[u8], label: &str) -> Result<[u8; 32]> {
    if input.len() != 32 {
        return Err(Error::from_reason(format!("{label} must be 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(input);
    Ok(out)
}

fn to_array_64(input: &[u8], label: &str) -> Result<[u8; 64]> {
    if input.len() != 64 {
        return Err(Error::from_reason(format!("{label} must be 64 bytes")));
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

#[napi(js_name = "x25519PublicKey")]
pub fn x25519_public_key(secret_key: Buffer) -> Result<Buffer> {
    let secret = to_array_32(secret_key.as_ref(), "secret key")?;
    Ok(Buffer::from(x25519(secret, x25519_basepoint()).to_vec()))
}

#[napi(js_name = "x25519SharedKey")]
pub fn x25519_shared_key(secret_key: Buffer, public_key: Buffer) -> Result<Buffer> {
    let secret = to_array_32(secret_key.as_ref(), "secret key")?;
    let public = to_array_32(public_key.as_ref(), "public key")?;
    Ok(Buffer::from(x25519(secret, public).to_vec()))
}

#[napi(js_name = "ed25519PublicKey")]
pub fn ed25519_public_key(secret_seed: Buffer) -> Result<Buffer> {
    let seed = to_array_32(secret_seed.as_ref(), "secret seed")?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(Buffer::from(sk.verifying_key().to_bytes().to_vec()))
}

#[napi(js_name = "ed25519Sign")]
pub fn ed25519_sign(secret_seed: Buffer, msg: Buffer) -> Result<Buffer> {
    let seed = to_array_32(secret_seed.as_ref(), "secret seed")?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(Buffer::from(sk.sign(msg.as_ref()).to_bytes().to_vec()))
}

#[napi(js_name = "ed25519Verify")]
pub fn ed25519_verify(public_key: Buffer, msg: Buffer, signature: Buffer) -> Result<bool> {
    let pk = to_array_32(public_key.as_ref(), "public key")?;
    let sig = to_array_64(signature.as_ref(), "signature")?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk).map_err(|_| Error::from_reason("invalid Ed25519 public key encoding"))?;
    let signature = Signature::from_bytes(&sig);
    Ok(verifying_key.verify(msg.as_ref(), &signature).is_ok())
}

#[napi(js_name = "axlsignPublicKey")]
pub fn axlsign_public_key(secret_key: Buffer) -> Result<Buffer> {
    let secret = to_array_32(secret_key.as_ref(), "secret key")?;
    let clamped = clamp_scalar(secret);
    let mut public = x25519(clamped, x25519_basepoint());
    public[31] &= 0x7f;
    Ok(Buffer::from(public.to_vec()))
}

#[napi(js_name = "axlsignSharedKey")]
pub fn axlsign_shared_key(secret_key: Buffer, public_key: Buffer) -> Result<Buffer> {
    let secret = to_array_32(secret_key.as_ref(), "secret key")?;
    let public = to_array_32(public_key.as_ref(), "public key")?;
    Ok(Buffer::from(x25519(secret, public).to_vec()))
}

#[napi(js_name = "axlsignSign")]
pub fn axlsign_sign(secret_key: Buffer, msg: Buffer) -> Result<Buffer> {
    let secret = to_array_32(secret_key.as_ref(), "secret key")?;
    let signature = sign_internal(secret, msg.as_ref(), None);
    Ok(Buffer::from(signature.to_vec()))
}

#[napi(js_name = "axlsignSignRnd")]
pub fn axlsign_sign_rnd(secret_key: Buffer, msg: Buffer, rnd: Buffer) -> Result<Buffer> {
    let secret = to_array_32(secret_key.as_ref(), "secret key")?;
    let random = to_array_64(rnd.as_ref(), "random")?;
    let signature = sign_internal(secret, msg.as_ref(), Some(random));
    Ok(Buffer::from(signature.to_vec()))
}

#[napi(js_name = "axlsignVerify")]
pub fn axlsign_verify(public_key: Buffer, msg: Buffer, signature: Buffer) -> Result<bool> {
    let public = to_array_32(public_key.as_ref(), "public key")?;
    let sig = to_array_64(signature.as_ref(), "signature")?;
    Ok(verify_internal(public, msg.as_ref(), sig))
}
