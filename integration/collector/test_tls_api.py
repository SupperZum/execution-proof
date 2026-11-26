import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from collector import Store, digest, encode
from tls_api import Endpoint, service


def issue(directory, name, issuer=None):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject).public_key(key.public_key())
               .issuer_name(issuer[0].subject if issuer else subject).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
               .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=None), critical=True))
    if name == "server":
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                                        critical=False)
    cert = builder.sign(issuer[1] if issuer else key, hashes.SHA256())
    (directory / (name + ".crt")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private = directory / (name + ".key")
    private.touch(mode=0o600)
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return cert, key


class TlsAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.tmp)
        ca = issue(self.root, "ca")
        issue(self.root, "server", ca)
        grants = {}
        for role in ("registrar", "sender", "reader", "relay", "recovery", "unknown"):
            cert, _ = issue(self.root, role, ca)
            if role != "unknown":
                grants[cert.fingerprint(hashes.SHA256()).hex()] = {"roles": [role], "attempts": ["attempt"]}
        self.store = Store(self.root)
        self.signer = ed25519.Ed25519PrivateKey.generate()
        self.options = self.root / "tls.json"
        self.options.write_bytes(encode(dict(cert=str(self.root / "server.crt"), key=str(self.root / "server.key"),
                                             client_ca=str(self.root / "ca.crt"), clients=grants,
                                             host="127.0.0.1", port=0)))
        self.server = service(self.options, self.store, self.signer, None)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.server.shutdown)

    def endpoint(self, role):
        client = self.root / (role + ".json")
        client.write_bytes(encode(dict(url="https://127.0.0.1:" + str(self.server.server_port),
                                       cert=str(self.root / (role + ".crt")), key=str(self.root / (role + ".key")),
                                       ca=str(self.root / "ca.crt"))))
        return Endpoint(client)

    def request(self, role, method, path, body=None):
        with closing(self.endpoint(role).connection()) as conn:
            conn.request(method, "/v1/attempts/" + path, body)
            res = conn.getresponse()
            return res.status, res.read()

    def test_separate_attempt_roles(self):
        trust = encode({"admission": {"attempt_id": "attempt"}})
        challenge = encode({"record_sha384": digest(b"record")})
        payload = {k: base64.b64encode(v).decode() for k, v in (("trust", trust), ("challenge", challenge))}
        for role in ("reader", "sender", "unknown", "relay"):
            self.assertEqual(self.request(role, "PUT", "attempt/context", encode(payload))[0], 403)
        for _ in range(2):
            self.assertEqual(self.request("registrar", "PUT", "attempt/context", encode(payload))[0], 200)
        payload["trust"] = base64.b64encode(trust + b" ").decode()
        self.assertEqual(self.request("registrar", "PUT", "attempt/context", encode(payload))[0], 409)
        self.assertEqual(self.request("reader", "GET", "attempt/trust"), (200, trust))
        self.assertEqual(self.request("reader", "GET", "foreign/trust")[0], 403)
        self.assertEqual(self.request("sender", "GET", "attempt/trust")[0], 403)
        self.assertEqual(self.request("relay", "GET", "attempt/receipt")[0], 404)
        loss = encode({"reason": "export_lost"})
        self.assertEqual(self.request("reader", "PUT", "attempt/loss", loss)[0], 403)
        self.assertEqual(self.request("recovery", "PUT", "attempt/loss", loss)[0], 200)
        result = json.loads(self.request("reader", "GET", "attempt")[1])
        self.assertEqual((result["delivery"], result["reason"]), ("unproven", "export_lost"))
        endpoint = self.endpoint("reader")
        endpoint.context = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        with closing(endpoint.connection()) as conn, self.assertRaises((ssl.SSLError, ConnectionError)):
            conn.request("GET", "/v1/attempts/attempt")
            conn.getresponse()
