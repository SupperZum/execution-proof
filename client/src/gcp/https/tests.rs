use super::*;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Instant,
};

fn key() -> PKey<Private> {
    PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap()
}
struct Fixture {
    roots: Vec<u8>,
    acceptor: Arc<SslAcceptor>,
}
fn fixture() -> Fixture {
    let ca_key = key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "in-memory-test-ca")
        .unwrap();
    let name = name.build();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name).unwrap();
    ca.set_issuer_name(&name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
        .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();
    let leaf_key = key();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_subject_name(&name).unwrap();
    leaf.set_issuer_name(ca.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(KeyUsage::new().digital_signature().build().unwrap())
        .unwrap();
    leaf.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("kbs.test")
        .dns("localhost")
        .build(&leaf.x509v3_context(Some(&ca), None))
        .unwrap();
    leaf.append_extension(san).unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    acceptor.set_certificate(&leaf.build()).unwrap();
    acceptor.set_private_key(&leaf_key).unwrap();
    acceptor.check_private_key().unwrap();
    Fixture {
        roots: ca.to_pem().unwrap(),
        acceptor: Arc::new(acceptor.build()),
    }
}
struct Server {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Option<Vec<u8>>>>,
}
impl Server {
    fn start(f: &Fixture, redirect: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let acceptor = f.acceptor.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let exit = stop.clone();
        let worker = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(2);
            loop {
                if exit.load(Ordering::Acquire) || Instant::now() >= end {
                    return None;
                }
                let (stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => return None,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut stream = acceptor.accept(stream).ok()?;
                let mut request = Vec::new();
                let mut buffer = [0u8; 512];
                loop {
                    let n = stream.read(&mut buffer).ok()?;
                    if n == 0 || request.len() + n > 8192 {
                        return None;
                    };
                    request.extend_from_slice(&buffer[..n]);
                    if request
                        .windows(4)
                        .position(|v| v == b"\r\n\r\n")
                        .is_some_and(|end| request.len() >= end + 6)
                    {
                        break;
                    }
                }
                let response = if redirect {
                    b"HTTP/1.1 302 Found\r\nLocation: https://foreign.test/credential\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\naccepted"
                        .as_slice()
                };
                stream.write_all(response).ok()?;
                return Some(request);
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> Option<Vec<u8>> {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn selected_ca_and_fixed_dns_reach_only_the_selected_tls_origin() {
    let f = fixture();
    let server = Server::start(&f, false);
    let origin = format!("https://kbs.test:{}", server.address.port());
    let transport =
        GcpHttpsTransport::with_trusted_roots(&origin, &f.roots, &[server.address]).unwrap();
    let result = runtime().block_on(transport.post(GcpLaunchRoute::Begin, b"{}"));
    assert_eq!(result.unwrap(), b"accepted");
    let request = server.finish().unwrap();
    assert!(request.starts_with(b"POST /kbs/launch/gcp/v2/begin HTTP/1.1\r\n"));
    assert!(String::from_utf8(request)
        .unwrap()
        .to_ascii_lowercase()
        .contains("host: kbs.test:"));
}
#[test]
fn unselected_ca_and_wrong_san_cannot_deliver_http_request() {
    for wrong_ca in [false, true] {
        let f = fixture();
        let foreign = fixture();
        let server = Server::start(&f, false);
        let origin = format!(
            "https://{}:{}",
            if wrong_ca { "kbs.test" } else { "foreign.test" },
            server.address.port()
        );
        let roots = if wrong_ca { &foreign.roots } else { &f.roots };
        let transport =
            GcpHttpsTransport::with_trusted_roots(&origin, roots, &[server.address]).unwrap();
        assert!(matches!(
            runtime().block_on(transport.post(GcpLaunchRoute::Begin, b"{}")),
            Err(ClientError::Transport)
        ));
        assert!(server.finish().is_none());
    }
}
#[test]
fn redirect_is_an_http_status_failure_without_new_origin_lookup() {
    let f = fixture();
    let server = Server::start(&f, true);
    let origin = format!("https://kbs.test:{}", server.address.port());
    let transport =
        GcpHttpsTransport::with_trusted_roots(&origin, &f.roots, &[server.address]).unwrap();
    assert!(matches!(
        runtime().block_on(transport.post(GcpLaunchRoute::Begin, b"{}")),
        Err(ClientError::HttpStatus)
    ));
    assert!(server.finish().is_some());
}

#[test]
fn failed_fixed_address_never_falls_back_to_localhost_resolution() {
    let f = fixture();
    let server = Server::start(&f, false);
    let origin = format!("https://localhost:{}", server.address.port());
    let refused = SocketAddr::new("127.0.0.2".parse().unwrap(), server.address.port());
    let transport = GcpHttpsTransport::with_trusted_roots(&origin, &f.roots, &[refused]).unwrap();
    assert!(matches!(
        runtime().block_on(transport.post(GcpLaunchRoute::Begin, b"{}")),
        Err(ClientError::Transport)
    ));
    assert!(server.finish().is_none());
}
#[test]
fn trusted_transport_requires_bounded_cert_only_roots_and_exact_fixed_addresses() {
    let f = fixture();
    let good: SocketAddr = "127.0.0.1:443".parse().unwrap();
    for origin in [
        "http://kbs.test",
        "https://127.0.0.1",
        "https://[::1]",
        "https://user@kbs.test",
        "https://kbs.test/path",
        "https://kbs.test/a/..",
        "https://kbs.test/%2e",
        "https://kbs.test?x",
        "https://kbs.test#fragment",
        "https://kbs.test:0",
        "https://kbs.test:00443",
        "https://kbs.test\\",
    ] {
        assert!(matches!(
            GcpHttpsTransport::with_trusted_roots(origin, &f.roots, &[good]),
            Err(ClientError::InvalidOrigin)
        ));
    }
    for addresses in [
        vec![],
        vec![good; 9],
        vec![good, good],
        vec!["127.0.0.1:444".parse().unwrap()],
        vec!["0.0.0.0:443".parse().unwrap()],
        vec!["224.0.0.1:443".parse().unwrap()],
        vec!["[::]:443".parse().unwrap()],
        vec!["[ff02::1]:443".parse().unwrap()],
        vec!["[::ffff:224.0.0.1]:443".parse().unwrap()],
    ] {
        assert!(matches!(
            GcpHttpsTransport::with_trusted_roots("https://kbs.test", &f.roots, &addresses),
            Err(ClientError::InvalidField)
        ));
    }
    let mut private = f.roots.clone();
    private.extend_from_slice(&key().private_key_to_pem_pkcs8().unwrap());
    for roots in [
        vec![],
        vec![b' '; (64 << 10) + 1],
        b"not-a-certificate".to_vec(),
        private,
        f.roots.repeat(17),
    ] {
        assert!(matches!(
            GcpHttpsTransport::with_trusted_roots("https://kbs.test", &roots, &[good]),
            Err(ClientError::InvalidField)
        ));
    }
}

#[test]
fn only_explicit_https_origins_and_static_routes_are_supported() {
    for origin in [
        "http://example.com",
        "https://user:password@example.com",
        "https://@example.com",
        "https://example.com/path",
        "https://example.com/a/..",
        "https://example.com/%2e",
        "https://example.com?query=1",
        "https://example.com#fragment",
        "https://example.com\\",
        " https://example.com",
    ] {
        assert!(matches!(
            GcpHttpsTransport::new(origin),
            Err(ClientError::InvalidOrigin)
        ));
    }
    for origin in [
        "https://example.com",
        "https://example.com/",
        "https://example.com:8443",
    ] {
        let transport = GcpHttpsTransport::new(origin).unwrap();
        for route in [
            GcpLaunchRoute::Begin,
            GcpLaunchRoute::Capture,
            GcpLaunchRoute::ResourceChallenge,
            GcpLaunchRoute::ResourceDecision,
            GcpLaunchRoute::CredentialDelivery,
        ] {
            let url = transport.origin.join(route.path()).unwrap();
            assert_eq!(url.origin(), transport.origin.origin());
            assert!(url.path().starts_with("/kbs/launch/gcp/v2/"));
        }
    }
}
