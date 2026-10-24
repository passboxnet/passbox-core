//! WebAssembly bindings for the Passbox core, used by the web client and the
//! browser extension.
//!
//! Build with `pnpm --filter @passbox/core-wasm build` (requires `wasm-pack`).

use passbox_core::generator::{self, PasswordOptions};
use passbox_core::secret_key::SecretKey;
use passbox_core::totp::Totp;
use wasm_bindgen::prelude::*;

fn js_error(err: impl ToString) -> JsError {
    JsError::new(&err.to_string())
}

/// Generates a password. `options` is a JSON object matching `PasswordOptions`;
/// missing fields use the defaults.
#[wasm_bindgen(js_name = generatePassword)]
pub fn generate_password(options_json: &str) -> Result<String, JsError> {
    let options: PasswordOptions = serde_json::from_str(options_json).map_err(js_error)?;
    generator::generate_password(&options).map_err(js_error)
}

/// Generates a new Secret Key in display format.
#[wasm_bindgen(js_name = generateSecretKey)]
pub fn generate_secret_key() -> Result<String, JsError> {
    Ok(SecretKey::generate().map_err(js_error)?.to_display_string())
}

/// Returns the normalized display format of a Secret Key, or an error if it is invalid.
#[wasm_bindgen(js_name = normalizeSecretKey)]
pub fn normalize_secret_key(input: &str) -> Result<String, JsError> {
    Ok(SecretKey::parse(input)
        .map_err(js_error)?
        .to_display_string())
}

/// Generates the TOTP code for an `otpauth://` URI or a Base32 secret at `unix_time` seconds.
#[wasm_bindgen(js_name = totpCode)]
pub fn totp_code(uri_or_secret: &str, unix_time: f64) -> Result<String, JsError> {
    let totp = if uri_or_secret.starts_with("otpauth://") {
        Totp::from_uri(uri_or_secret)
    } else {
        Totp::from_base32(uri_or_secret)
    }
    .map_err(js_error)?;
    // Time values from JavaScript are non-negative and well within u64 range.
    Ok(totp.generate(unix_time.max(0.0) as u64))
}
