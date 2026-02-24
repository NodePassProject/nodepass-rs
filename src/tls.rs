use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Generate a self-signed ECDSA P-256 certificate and return a rustls ServerConfig
/// along with the certificate DER bytes (for fingerprint verification)
pub fn new_tls_config() -> anyhow::Result<(Arc<ServerConfig>, Vec<u8>)> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::default();
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    let cert = params.self_signed(&key_pair)?;
    let cert_der_bytes = cert.der().to_vec();
    let cert_der = CertificateDer::from(cert_der_bytes.clone());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((Arc::new(config), cert_der_bytes))
}

/// Load TLS config from certificate and key files
pub fn load_tls_config(crt_path: &str, key_path: &str) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_data = std::fs::read(crt_path)?;
    let key_data = std::fs::read(key_path)?;

    let certs = rustls_pemfile::certs(&mut &cert_data[..])
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_data[..])?.ok_or_else(|| {
        anyhow::anyhow!("no private key found in {}", key_path)
    })?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Load a CertifiedKey from cert and key files
fn load_certified_key(crt_path: &str, key_path: &str) -> anyhow::Result<rustls::sign::CertifiedKey> {
    let cert_data = std::fs::read(crt_path)?;
    let key_data = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_data[..])
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_data[..])?.ok_or_else(|| {
        anyhow::anyhow!("no private key found in {}", key_path)
    })?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported key type: {}", e))?;

    Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
}

/// Certificate resolver that reloads certificates from disk periodically
#[derive(Debug)]
struct ReloadingCertResolver {
    crt_path: String,
    key_path: String,
    cached_key: Mutex<Arc<rustls::sign::CertifiedKey>>,
    last_reload: Mutex<Instant>,
}

impl ReloadingCertResolver {
    fn new(crt_path: String, key_path: String, initial_key: rustls::sign::CertifiedKey) -> Self {
        Self {
            crt_path,
            key_path,
            cached_key: Mutex::new(Arc::new(initial_key)),
            last_reload: Mutex::new(Instant::now()),
        }
    }
}

impl rustls::server::ResolvesServerCert for ReloadingCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let mut last_reload = self.last_reload.lock().unwrap();
        if last_reload.elapsed() >= crate::config::RELOAD_INTERVAL() {
            match load_certified_key(&self.crt_path, &self.key_path) {
                Ok(new_key) => {
                    let mut cached = self.cached_key.lock().unwrap();
                    *cached = Arc::new(new_key);
                }
                Err(e) => {
                    eprintln!("Failed to reload certificate: {}", e);
                }
            }
            *last_reload = Instant::now();
        }
        drop(last_reload);

        let cached = self.cached_key.lock().unwrap();
        Some(cached.clone())
    }
}

/// Load TLS config from certificate and key files with periodic hot-reload support
pub fn load_tls_config_reloading(crt_path: &str, key_path: &str) -> anyhow::Result<Arc<ServerConfig>> {
    let certified_key = load_certified_key(crt_path, key_path)?;

    let resolver = ReloadingCertResolver::new(
        crt_path.to_string(),
        key_path.to_string(),
        certified_key,
    );

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Get certificate fingerprint in sha256:XX:XX:... format
pub fn format_cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(cert_der);
    let hex_str = hex::encode_upper(hash);
    let mut formatted = String::with_capacity(hex_str.len() + hex_str.len() / 2);
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        if i > 0 {
            formatted.push(':');
        }
        formatted.push(chunk[0] as char);
        formatted.push(chunk[1] as char);
    }
    format!("sha256:{}", formatted)
}

/// Create a rustls ClientConfig that skips server certificate verification
pub fn insecure_client_config() -> Arc<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Arc::new(config)
}

#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
