// Package managementrelay authenticates an untrusted management TLS peer before
// relaying bytes to one fixed Kata socket. It grants no proof authority.
package managementrelay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"strings"
	"time"
)

const BackendSocket = "/run/onb17/kata-agent.sock"
const ListenPort = 15150
const BufferBytes = 16 << 10
const MaxCredentialBytes = 64 << 10
const MaxKeyBytes = 16 << 10
const MaxConfigBytes = 16 << 10

var ErrConfiguration = errors.New("management relay configuration rejected")
var ErrCredentials = errors.New("management relay credentials rejected")
var ErrBudget = errors.New("management relay transfer budget exceeded")
var ErrServing = errors.New("management relay listener failed")

// Config must be supplied by the authenticated closed startup owner. Parsing it
// does not establish immutable provenance. Credentials are supplied separately.
type Config struct {
	Version               int    `json:"version"`
	Purpose               string `json:"purpose"`
	ListenIP              string `json:"listen_ip"`
	ServerName            string `json:"server_name"`
	ClientCAPEMSHA384     string `json:"client_ca_pem_sha384"`
	ServerCertPEMSHA384   string `json:"server_cert_pem_sha384"`
	ClientLeafDERSHA384   string `json:"client_leaf_der_sha384"`
	MaxConnections        int    `json:"max_connections"`
	HandshakeMilliseconds int    `json:"handshake_milliseconds"`
	DialMilliseconds      int    `json:"dial_milliseconds"`
	IdleMilliseconds      int    `json:"idle_milliseconds"`
	SessionMilliseconds   int    `json:"session_milliseconds"`
	MaxBytes              int64  `json:"max_bytes"`
}

// Credentials are consumed by New and never formatted or logged. Go may retain
// copies of parsed private key material; the startup process owns its lifetime.
type Credentials struct{ ClientCAPEM, ServerCertPEM, ServerKeyPEM []byte }

func (c Config) validate() error {
	ip, err := netip.ParseAddr(c.ListenIP)
	if c.Version != 1 || c.Purpose != "onb17.gcp-management-tls-relay.v1" || err != nil || !ip.Is4() || ip.IsMulticast() || !serverName(c.ServerName) {
		return ErrConfiguration
	}
	for _, h := range []string{c.ClientCAPEMSHA384, c.ServerCertPEMSHA384, c.ClientLeafDERSHA384} {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 48 || hex.EncodeToString(b) != h || bytes.Equal(b, make([]byte, 48)) {
			return ErrConfiguration
		}
	}
	if c.MaxConnections < 1 || c.MaxConnections > 8 || c.HandshakeMilliseconds < 1 || c.HandshakeMilliseconds > 10000 || c.DialMilliseconds < 1 || c.DialMilliseconds > 5000 || c.IdleMilliseconds < 1 || c.IdleMilliseconds > 30000 || c.SessionMilliseconds < 1 || c.SessionMilliseconds > 300000 || c.MaxBytes < 1 || c.MaxBytes > 64<<20 {
		return ErrConfiguration
	}
	if c.HandshakeMilliseconds > c.SessionMilliseconds || c.DialMilliseconds > c.SessionMilliseconds || c.IdleMilliseconds > c.SessionMilliseconds {
		return ErrConfiguration
	}
	return nil
}
func serverName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}
func digest(b []byte) string { sum := sha512.Sum384(b); return hex.EncodeToString(sum[:]) }

// DecodeConfig rejects unknown, duplicate, missing, and trailing fields. The
// fixed byte ceiling also bounds parsing allocations before semantic checks.
func DecodeConfig(wire []byte) (Config, error) {
	var c Config
	if len(wire) == 0 || len(wire) > MaxConfigBytes {
		return c, ErrConfiguration
	}
	// Decoder.DisallowUnknownFields alone accepts duplicate object members.
	scan := json.NewDecoder(bytes.NewReader(wire))
	if token, err := scan.Token(); err != nil || token != json.Delim('{') {
		return c, ErrConfiguration
	}
	seen := map[string]bool{}
	for scan.More() {
		t, err := scan.Token()
		k, ok := t.(string)
		if err != nil || !ok || seen[k] {
			return c, ErrConfiguration
		}
		switch k {
		case "version", "purpose", "listen_ip", "server_name", "client_ca_pem_sha384", "server_cert_pem_sha384", "client_leaf_der_sha384", "max_connections", "handshake_milliseconds", "dial_milliseconds", "idle_milliseconds", "session_milliseconds", "max_bytes":
		default:
			return c, ErrConfiguration
		}
		seen[k] = true
		var raw json.RawMessage
		if scan.Decode(&raw) != nil {
			return c, ErrConfiguration
		}
	}
	if _, err := scan.Token(); err != nil {
		return c, ErrConfiguration
	}
	if _, err := scan.Token(); err != io.EOF {
		return c, ErrConfiguration
	}
	if len(seen) != 13 {
		return c, ErrConfiguration
	}
	dec := json.NewDecoder(bytes.NewReader(wire))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil || c.validate() != nil {
		return Config{}, ErrConfiguration
	}
	return c, nil
}

func tlsConfiguration(c Config, credentials Credentials) (*tls.Config, error) {
	if len(credentials.ClientCAPEM) == 0 || len(credentials.ClientCAPEM) > MaxCredentialBytes || len(credentials.ServerCertPEM) == 0 || len(credentials.ServerCertPEM) > MaxCredentialBytes || len(credentials.ServerKeyPEM) == 0 || len(credentials.ServerKeyPEM) > MaxKeyBytes || digest(credentials.ClientCAPEM) != c.ClientCAPEMSHA384 || digest(credentials.ServerCertPEM) != c.ServerCertPEMSHA384 {
		return nil, ErrCredentials
	}
	roots := x509.NewCertPool()
	remainder := credentials.ClientCAPEM
	count := 0
	for len(bytes.TrimSpace(remainder)) != 0 {
		block, rest := pem.Decode(remainder)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrCredentials
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrCredentials
		}
		roots.AddCert(cert)
		remainder = rest
		count++
		if count > 8 {
			return nil, ErrCredentials
		}
	}
	if count == 0 {
		return nil, ErrCredentials
	}
	remainder = credentials.ServerCertPEM
	count = 0
	for len(bytes.TrimSpace(remainder)) != 0 {
		block, rest := pem.Decode(remainder)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrCredentials
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, ErrCredentials
		}
		count++
		if count > 8 {
			return nil, ErrCredentials
		}
		remainder = rest
	}
	key, rest := pem.Decode(credentials.ServerKeyPEM)
	if key == nil || key.Type != "PRIVATE KEY" || len(key.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrCredentials
	}
	pair, err := tls.X509KeyPair(credentials.ServerCertPEM, credentials.ServerKeyPEM)
	if err != nil || len(pair.Certificate) == 0 || len(pair.Certificate) > 8 {
		return nil, ErrCredentials
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(c.ServerName) != nil {
		return nil, ErrCredentials
	}
	if !managementKey(leaf.PublicKey) {
		return nil, ErrCredentials
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || digest(leaf.Raw) == c.ClientLeafDERSHA384 {
		return nil, ErrCredentials
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return nil, ErrCredentials
	}
	pair.Leaf = leaf
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		Certificates: []tls.Certificate{pair}, SessionTicketsDisabled: true,
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 || !managementKey(s.PeerCertificates[0].PublicKey) || digest(s.PeerCertificates[0].Raw) != c.ClientLeafDERSHA384 || bytes.Equal(s.PeerCertificates[0].RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
				return ErrCredentials
			}
			return nil
		},
	}, nil
}

func managementKey(key any) bool {
	public, ok := key.(*ecdsa.PublicKey)
	return ok && public.Curve == elliptic.P256()
}
