//! Android-specific initialization.
//!
//! HTTPS certificates are verified by Android's own trust manager through
//! `rustls-platform-verifier`, which calls into the JVM. It needs the app
//! context once per process, before the first request; without it every TLS
//! connection fails. The app calls
//! `dev.passbox.ffi.PassboxAndroid.initialize(context)` (a Kotlin
//! `external fun` in the Android app) right after loading the library.

use jni::EnvUnowned;
use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JClass, JObject};

#[jni::jni_mangle("dev.passbox.ffi.PassboxAndroid")]
pub extern "system" fn initialize<'caller>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    env.with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .resolve::<ThrowRuntimeExAndDefault>();
}
