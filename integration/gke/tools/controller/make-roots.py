#!/usr/bin/env python3
"""Generate operator-selected prototype roots, never a qualification or policy.

Private keys are create-only 0700/0600 inputs. Public outputs authenticate
only future prototype artifacts. They are neither production release keys nor
evidence of hardware execution. No Cloud SA credential is handled here.
"""
import argparse
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import resource

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


def store(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def create(output, private, kbs_dns, registry_dns, authority_dns):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
        raise ValueError('dump protection')
    output.mkdir(mode=0o700, parents=False)
    private.mkdir(mode=0o700, parents=False)
    now = datetime.now(timezone.utc)
    roots, files, inventory = {}, {}, []

    def secret(name, raw):
        store(private/name, raw, 0o600)

    def public(name, raw):
        store(output/name, raw, 0o444)
        files[name] = {'bytes': len(raw), 'sha384': hashlib.sha384(raw).hexdigest()}

    for role in ('authority', 'build', 'reference', 'kbs-proof', 'qualification', 'tenant'):
        key = ed25519.Ed25519PrivateKey.generate()
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        # ring's strict PKCS8v2 OneAsymmetricKey encoding includes its public key.
        pkcs8 = bytes.fromhex('3051020101300506032b657004220420') + seed + bytes.fromhex('812100') + pub
        if len(pkcs8) != 83: raise ValueError('PKCS8v2 shape')
        secret(role+'.pk8', pkcs8)
        public(role+'.pub', pub)
        roots[role] = list(pub)
        message = b'onb17.manual-prototype-root-selfcheck.v1'
        key.public_key().verify(key.sign(message), message)

    def tls(role, dns, usage):
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Execution Proof '+role+' CA')])
        ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=1))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
              .sign(ca_key, hashes.SHA256()))
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns)])
        leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
        ca.public_key().verify(ca.signature, ca.tbs_certificate_bytes, ec.ECDSA(ca.signature_hash_algorithm))
        public(role+'-ca.pem', ca.public_bytes(serialization.Encoding.PEM))
        public(role+'-cert.pem', leaf.public_bytes(serialization.Encoding.PEM))
        # CA signing keys are discarded: only the selected leaf remains usable.
        secret(role+'-key.pem', key.private_bytes(serialization.Encoding.PEM,
               serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        inventory.append({'role': role, 'dns': dns,
                          'leaf_der_sha384': hashlib.sha384(leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
                          'not_after_utc': (now+timedelta(days=1)).isoformat(), 'eku': usage.dotted_string})

    tls('management-client', 'execution-proof-controller', ExtendedKeyUsageOID.CLIENT_AUTH)
    tls('management-server', 'podvm-server', ExtendedKeyUsageOID.SERVER_AUTH)
    tls('authority-tls', authority_dns, ExtendedKeyUsageOID.SERVER_AUTH)
    tls('kbs-tls', kbs_dns, ExtendedKeyUsageOID.SERVER_AUTH)
    tls('registry-tls', registry_dns, ExtendedKeyUsageOID.SERVER_AUTH)
    image = ec.generate_private_key(ec.SECP256R1())
    secret('image-signing-key.pem', image.private_bytes(serialization.Encoding.PEM,
           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public('image-signing-public.pem', image.public_key().public_bytes(serialization.Encoding.PEM,
           serialization.PublicFormat.SubjectPublicKeyInfo))
    receipt = {'schema': 'onb17.manual-prototype-rootset.v1', 'created_utc': now.isoformat(),
               'public_roots': roots, 'files': files, 'tls': inventory,
               'source_sha384': hashlib.sha384(Path(__file__).read_bytes()).hexdigest(),
               'private_key_hashes_retained': False, 'qualification_signed': False,
               'cloud_mutations_performed': False, 'producer_qualified': False, 'execution_verified': False}
    public('rootset.json', (json.dumps(receipt, indent=2)+'\n').encode())
    print(json.dumps({'status': 'PROTOTYPE_PUBLIC_ROOTS_SELECTED', 'public_directory': str(output),
                      'qualification_signed': False, 'cloud_mutations_performed': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--kbs-dns', required=True)
    parser.add_argument('--registry-dns', required=True)
    parser.add_argument('--authority-dns', required=True)
    args = parser.parse_args()
    try: create(args.output.resolve(), args.private.resolve(), args.kbs_dns, args.registry_dns, args.authority_dns)
    except Exception: raise SystemExit('prototype root generation rejected') from None
