//! TLS 1.3 on every connection, bound to the SMB proof (see DESIGN-TLS.md). The receiver uses an ephemeral
//! self-signed key generated at start; the client accepts any key but checks the handshake signature. Who is on the
//! other end is proven afterwards: both sides derive the TLS exporter `E`, the SMB ticket carries `E`, and a man in
//! the middle (two TLS sessions, two different exporters) can't rewrite the ticket without the user's credentials.
//! Data and feedback connections join with a token derived from the control connection's `E`.

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme, StreamOwned};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, OnceLock};

/// Exporter label for the session binding; both ends must use the same.
const LABEL: &[u8] = b"scopy-binding-v1";

/// The 32-byte TLS exporter of one connection: identical on both ends of it, different for every other session.
pub type Binding = [u8; 32];

trait Duplex: Read + Write + Send {}
impl<T: Read + Write + Send> Duplex for T {}

/// One TLS connection that a `BufReader` and a `BufWriter` share. scopy never reads and writes one connection from
/// two threads at the same time, so the lock is never contended; it only lets both buffers own a handle.
#[derive(Clone)]
pub struct Tls(Arc<Mutex<Box<dyn Duplex>>>);

impl Read for Tls {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
}

impl Write for Tls {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config() -> Result<Arc<ServerConfig>> {
    static CFG: OnceLock<Arc<ServerConfig>> = OnceLock::new();
    if let Some(c) = CFG.get() {
        return Ok(c.clone());
    }
    let key = rcgen::generate_simple_self_signed(vec!["scopy".to_string()]).context("cannot create the TLS key")?;
    let cert = CertificateDer::from(key.cert.der().to_vec());
    let _ = CERT_FP.set(fingerprint(&cert));
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.key_pair.serialize_der()));
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], der)?;
    Ok(CFG.get_or_init(|| Arc::new(cfg)).clone())
}

/// The receiver's certificate, as a fingerprint (BLAKE3 of the DER, hex).
static CERT_FP: OnceLock<String> = OnceLock::new();
/// SSH sessions (ssh.rs): the only certificate the client accepts, announced over the SSH channel (which SSH has
/// authenticated). Without it the client accepts any key and the SMB ticket proves the session (see the top).
/// The only server certificate accepted (an SSH session's or a daemon's, announced over SSH); a daemon sign-in
/// that is renewed may bring a new one (the daemon's key is made at its start).
static PIN: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

fn fingerprint(cert: &CertificateDer) -> String {
    blake3::hash(cert.as_ref()).to_hex().to_string()
}

/// This receiver's certificate fingerprint (creates the key if needed).
pub fn server_fingerprint() -> Result<String> {
    server_config()?;
    Ok(CERT_FP.get().cloned().unwrap_or_default())
}

/// From now on this process accepts only the server certificate with this fingerprint.
pub fn pin_server(fp: &str) {
    *PIN.write().unwrap() = Some(fp.to_string());
}

fn client_config() -> Result<Arc<ClientConfig>> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(c) = CFG.get() {
        return Ok(c.clone());
    }
    let p = provider();
    let cfg = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyKey(p)))
        .with_no_client_auth();
    Ok(CFG.get_or_init(|| Arc::new(cfg)).clone())
}

/// Accepts any server key (there is no PKI: the SMB proof authenticates the session) but still verifies that the
/// handshake was signed with that key, so the exporter really belongs to this session.
#[derive(Debug)]
struct AnyKey(Arc<CryptoProvider>);

impl ServerCertVerifier for AnyKey {
    fn verify_server_cert(&self, cert: &CertificateDer, _: &[CertificateDer], _: &ServerName, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        match PIN.read().unwrap().as_deref() {
            Some(p) if p != fingerprint(cert) => Err(rustls::Error::General(
                "the receiver's certificate is not the one announced at sign-in (a daemon that restarted has a new one: sign in again)".into(),
            )),
            _ => Ok(ServerCertVerified::assertion()),
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Client side: TLS handshake on a connected socket, then the binding.
pub fn connect(mut tcp: TcpStream) -> Result<(Tls, Binding)> {
    let mut conn = ClientConnection::new(client_config()?, ServerName::try_from("scopy")?.to_owned())?;
    while conn.is_handshaking() {
        // A pinned certificate that doesn't match says so itself; the version hint is for anything else.
        conn.complete_io(&mut tcp).map_err(|e| {
            let pinned = e.to_string().contains("announced at sign-in");
            anyhow::Error::new(e).context(if pinned { "TLS handshake failed" } else { "TLS handshake failed (is the receiver older than scopy 0.9?)" })
        })?;
    }
    let mut b = [0u8; 32];
    conn.export_keying_material(&mut b, LABEL, None)?;
    Ok((Tls(Arc::new(Mutex::new(Box::new(StreamOwned::new(conn, tcp))))), b))
}

/// Receiver side: TLS handshake on an accepted socket, then the binding.
pub fn accept(mut tcp: TcpStream) -> Result<(Tls, Binding)> {
    let mut conn = ServerConnection::new(server_config()?)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp).context("TLS handshake failed")?;
    }
    let mut b = [0u8; 32];
    conn.export_keying_material(&mut b, LABEL, None)?;
    Ok((Tls(Arc::new(Mutex::new(Box::new(StreamOwned::new(conn, tcp))))), b))
}

/// Hex form of the binding, as it goes into the SMB ticket.
pub fn hex(b: &Binding) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The token a data or feedback connection presents to join session `sid`: only the holder of the control
/// connection's binding can compute it, so a sniffed or guessed session id is useless.
pub fn join_token(b: &Binding, sid: &str) -> String {
    let mut msg = b"join:".to_vec();
    msg.extend_from_slice(sid.as_bytes());
    blake3::keyed_hash(b, &msg).to_hex().to_string()
}

/// The ticket text for a binding: `nonce:hex(E)`.
pub fn ticket(nonce: &str, b: &Binding) -> String {
    format!("{nonce}:{}", hex(b))
}

/// Checks a ticket read back against our own nonce and binding.
pub fn check_ticket(found: &str, nonce: &str, b: &Binding) -> Result<()> {
    if found.trim_end() == ticket(nonce, b) {
        return Ok(());
    }
    if found.split(':').next() == Some(nonce) {
        bail!("access check failed: the ticket belongs to a different TLS session (someone between client and receiver?)");
    }
    bail!("access check failed: ticket not found or wrong")
}

/// A connection that starts with scopy's plain hello (`SCPY`) instead of a TLS ClientHello comes from a client
/// older than 0.9.
pub fn is_plain_scopy(tcp: &TcpStream) -> bool {
    let mut first = [0u8; 4];
    matches!(tcp.peek(&mut first), Ok(4) if &first == crate::proto::MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> ((Tls, Binding), (Tls, Binding)) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || accept(l.accept().unwrap().0).unwrap());
        let client = connect(TcpStream::connect(addr).unwrap()).unwrap();
        (client, server.join().unwrap())
    }

    #[test]
    fn both_ends_share_the_binding_and_data_flows() {
        let ((mut c, cb), (mut s, sb)) = pair();
        assert_eq!(cb, sb);
        c.write_all(b"hello").unwrap();
        c.flush().unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        // Another session has another binding.
        let ((_, cb2), _) = pair();
        assert_ne!(cb, cb2);
    }

    #[test]
    fn ticket_from_another_session_is_refused() {
        // A man in the middle runs two TLS sessions: the client writes its binding into the ticket, the receiver
        // checks against its own, different one.
        let (client_side, receiver_side) = ([1u8; 32], [2u8; 32]);
        let written = ticket("n0nce", &client_side);
        assert!(check_ticket(&written, "n0nce", &client_side).is_ok());
        let e = check_ticket(&written, "n0nce", &receiver_side).unwrap_err().to_string();
        assert!(e.contains("different TLS session"), "{e}");
        assert!(check_ticket("other", "n0nce", &receiver_side).is_err());
        assert_ne!(join_token(&client_side, "s1"), join_token(&receiver_side, "s1"));
        assert_ne!(join_token(&client_side, "s1"), join_token(&client_side, "s2"));
    }
}
