//! Login with OPAQUE (RFC 9807), an asymmetric password-authenticated key
//! exchange. The server stores a registration record instead of a password
//! hash and never sees the password, not even during login.
//!
//! The OPAQUE "password" is the `auth_secret` from [`crate::kdf`], which is
//! derived from both the master password and the Secret Key. Argon2id already
//! ran during that derivation, so the OPAQUE key stretching function is the
//! identity.
//!
//! All messages are exchanged as byte strings; the transport encodes them.
//! Client and server helpers both live here so they always agree on the
//! cipher suite and context.

use opaque_ke::ksf::Identity;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    Ristretto255, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, TripleDh,
};
use opaque_rand_core::OsRng;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// The Passbox OPAQUE cipher suite: ristretto255, 3DH with SHA-512.
pub struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, opaque_sha2::Sha512>;
    type Ksf = Identity;
}

/// Context string that binds every login to Passbox protocol version 1.
const CONTEXT: &[u8] = b"passbox/v1/login";

fn protocol_error<E>(_: E) -> Error {
    Error::Protocol
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client side of a registration. Created by [`ClientRegistrationFlow::start`].
pub struct ClientRegistrationFlow {
    state: ClientRegistration<Suite>,
    password: Zeroizing<Vec<u8>>,
}

impl ClientRegistrationFlow {
    /// Starts a registration. Returns the flow and the request for the server.
    pub fn start(auth_secret: &[u8]) -> Result<(Self, Vec<u8>)> {
        let result =
            ClientRegistration::<Suite>::start(&mut OsRng, auth_secret).map_err(protocol_error)?;
        let flow = Self {
            state: result.state,
            password: Zeroizing::new(auth_secret.to_vec()),
        };
        Ok((flow, result.message.serialize().to_vec()))
    }

    /// Finishes the registration with the server's response. Returns the
    /// upload message for the server.
    pub fn finish(self, response: &[u8]) -> Result<Vec<u8>> {
        let response =
            RegistrationResponse::<Suite>::deserialize(response).map_err(protocol_error)?;
        let result = self
            .state
            .finish(
                &mut OsRng,
                &self.password,
                response,
                ClientRegistrationFinishParameters::new(Identifiers::default(), None),
            )
            .map_err(protocol_error)?;
        Ok(result.message.serialize().to_vec())
    }
}

/// Client side of a login. Created by [`ClientLoginFlow::start`].
pub struct ClientLoginFlow {
    state: ClientLogin<Suite>,
    password: Zeroizing<Vec<u8>>,
}

/// Result of a successful client login.
pub struct ClientLoginFinish {
    /// Message for the server.
    pub finalization: Vec<u8>,
    /// Key shared with the server; identical on both sides.
    pub session_key: Zeroizing<Vec<u8>>,
}

impl ClientLoginFlow {
    /// Starts a login. Returns the flow and the request for the server.
    pub fn start(auth_secret: &[u8]) -> Result<(Self, Vec<u8>)> {
        let result =
            ClientLogin::<Suite>::start(&mut OsRng, auth_secret).map_err(protocol_error)?;
        let flow = Self {
            state: result.state,
            password: Zeroizing::new(auth_secret.to_vec()),
        };
        Ok((flow, result.message.serialize().to_vec()))
    }

    /// Finishes the login with the server's response. Fails with
    /// [`Error::InvalidCredentials`] if the password or Secret Key is wrong.
    pub fn finish(self, response: &[u8]) -> Result<ClientLoginFinish> {
        let response =
            CredentialResponse::<Suite>::deserialize(response).map_err(protocol_error)?;
        let result = self
            .state
            .finish(
                &mut OsRng,
                &self.password,
                response,
                ClientLoginFinishParameters::new(Some(CONTEXT), Identifiers::default(), None),
            )
            .map_err(|_| Error::InvalidCredentials)?;
        Ok(ClientLoginFinish {
            finalization: result.message.serialize().to_vec(),
            session_key: Zeroizing::new(result.session_key.to_vec()),
        })
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The server's long-term OPAQUE secrets. Must be generated once and persisted.
pub struct ServerKeys(ServerSetup<Suite>);

impl ServerKeys {
    /// Generates new server keys.
    pub fn generate() -> Self {
        Self(ServerSetup::<Suite>::new(&mut OsRng))
    }

    /// Serializes the keys for storage. The output is secret.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.serialize().to_vec())
    }

    /// Restores keys from [`ServerKeys::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ServerSetup::<Suite>::deserialize(bytes)
            .map(Self)
            .map_err(protocol_error)
    }

    /// Answers a registration request for `credential_id`.
    pub fn registration_response(&self, request: &[u8], credential_id: &[u8]) -> Result<Vec<u8>> {
        let request = RegistrationRequest::<Suite>::deserialize(request).map_err(protocol_error)?;
        let result = ServerRegistration::<Suite>::start(&self.0, request, credential_id)
            .map_err(protocol_error)?;
        Ok(result.message.serialize().to_vec())
    }

    /// Answers a login request. Pass `None` as `record` for unknown users: the
    /// response is then indistinguishable from a real one, so attackers cannot
    /// probe which accounts exist. Returns the state to keep for
    /// [`finish_login`] and the response for the client.
    pub fn start_login(
        &self,
        record: Option<&[u8]>,
        request: &[u8],
        credential_id: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
        let record = record
            .map(ServerRegistration::<Suite>::deserialize)
            .transpose()
            .map_err(protocol_error)?;
        let request = CredentialRequest::<Suite>::deserialize(request).map_err(protocol_error)?;
        let result = ServerLogin::start(
            &mut OsRng,
            &self.0,
            record,
            request,
            credential_id,
            server_parameters(),
        )
        .map_err(protocol_error)?;
        Ok((
            Zeroizing::new(result.state.serialize().to_vec()),
            result.message.serialize().to_vec(),
        ))
    }
}

fn server_parameters() -> ServerLoginParameters<'static, 'static> {
    ServerLoginParameters {
        context: Some(CONTEXT),
        identifiers: Identifiers::default(),
    }
}

/// Validates a registration upload and returns the record to store.
pub fn registration_record(upload: &[u8]) -> Result<Vec<u8>> {
    let upload = RegistrationUpload::<Suite>::deserialize(upload).map_err(protocol_error)?;
    Ok(ServerRegistration::<Suite>::finish(upload)
        .serialize()
        .to_vec())
}

/// Verifies the client's final login message. Returns the shared session key,
/// or [`Error::InvalidCredentials`] if the client did not know the password.
pub fn finish_login(state: &[u8], finalization: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let state = ServerLogin::<Suite>::deserialize(state).map_err(protocol_error)?;
    let finalization =
        CredentialFinalization::<Suite>::deserialize(finalization).map_err(protocol_error)?;
    let result = state
        .finish(finalization, server_parameters())
        .map_err(|_| Error::InvalidCredentials)?;
    Ok(Zeroizing::new(result.session_key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(server: &ServerKeys, password: &[u8], id: &[u8]) -> Vec<u8> {
        let (flow, request) = ClientRegistrationFlow::start(password).unwrap();
        let response = server.registration_response(&request, id).unwrap();
        let upload = flow.finish(&response).unwrap();
        registration_record(&upload).unwrap()
    }

    #[test]
    fn register_and_login() {
        let server = ServerKeys::generate();
        let record = register(&server, b"secret", b"acc_1");

        let (flow, request) = ClientLoginFlow::start(b"secret").unwrap();
        let (state, response) = server
            .start_login(Some(&record), &request, b"acc_1")
            .unwrap();
        let client = flow.finish(&response).unwrap();
        let server_key = finish_login(&state, &client.finalization).unwrap();
        assert_eq!(*client.session_key, *server_key);
    }

    #[test]
    fn wrong_password_fails_on_the_client() {
        let server = ServerKeys::generate();
        let record = register(&server, b"secret", b"acc_1");

        let (flow, request) = ClientLoginFlow::start(b"guess").unwrap();
        let (_, response) = server
            .start_login(Some(&record), &request, b"acc_1")
            .unwrap();
        assert_eq!(
            flow.finish(&response).err(),
            Some(Error::InvalidCredentials)
        );
    }

    #[test]
    fn unknown_user_gets_a_response_but_cannot_log_in() {
        let server = ServerKeys::generate();
        let (flow, request) = ClientLoginFlow::start(b"secret").unwrap();
        let (_, response) = server.start_login(None, &request, b"nobody").unwrap();
        assert_eq!(
            flow.finish(&response).err(),
            Some(Error::InvalidCredentials)
        );
    }

    #[test]
    fn forged_finalization_is_rejected() {
        let server = ServerKeys::generate();
        let record = register(&server, b"secret", b"acc_1");
        let (_, request) = ClientLoginFlow::start(b"secret").unwrap();
        let (state, _) = server
            .start_login(Some(&record), &request, b"acc_1")
            .unwrap();

        // A finalization from a different login session must not verify.
        let (other_flow, other_request) = ClientLoginFlow::start(b"secret").unwrap();
        let (_, other_response) = server
            .start_login(Some(&record), &other_request, b"acc_1")
            .unwrap();
        let other = other_flow.finish(&other_response).unwrap();
        assert_eq!(
            finish_login(&state, &other.finalization).err(),
            Some(Error::InvalidCredentials)
        );
    }

    #[test]
    fn server_keys_round_trip() {
        let server = ServerKeys::generate();
        let restored = ServerKeys::from_bytes(&server.to_bytes()).unwrap();
        let record = register(&restored, b"secret", b"acc_1");
        let (flow, request) = ClientLoginFlow::start(b"secret").unwrap();
        let (_, response) = server
            .start_login(Some(&record), &request, b"acc_1")
            .unwrap();
        assert!(flow.finish(&response).is_ok());
    }
}
