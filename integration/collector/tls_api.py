"""Private collector API with mutual TLS and attempt-scoped client credentials."""
import base64
from hashlib import sha256
from http.server import HTTPServer
import json
import re
import ssl
from pathlib import Path
from urllib.parse import urlsplit
import http.client

from collector import CHALLENGE_LIMIT, ID, PREFIX, TRUST_LIMIT, Conflict, Handler, encode


class Endpoint:
    def __init__(self, config):
        settings = json.loads(Path(config).read_bytes())
        url = urlsplit(settings["url"])
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("expected an HTTPS collector origin")
        self.host, self.port = url.hostname, url.port or 443
        self.context = ssl.create_default_context(cafile=settings["ca"])
        self.context.load_cert_chain(settings["cert"], settings["key"])

    def connection(self):
        return http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=90)


def allowed(grant, role, attempt):
    if role not in grant.get("roles", []):
        return False
    return attempt in grant.get("attempts", []) or any(
        prefix and attempt.startswith(prefix) for prefix in grant.get("prefixes", []))


class PrivateHandler(Handler):
    def permitted(self, role, attempt):
        fingerprint = sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        return allowed(self.server.grants.get(fingerprint, {}), role, attempt)

    def do_GET(self):
        matched = re.fullmatch(PREFIX + f"({ID})(?:/(pack|trust|challenge|verdict|receipt))?", self.path)
        if not matched:
            return self.reply(404)
        attempt, field = matched.groups()
        enabled = (self.permitted("reader", attempt) or
                   (field == "verdict" and self.permitted("sender", attempt)) or
                   (field == "receipt" and self.permitted("relay", attempt)))
        if not enabled:
            return self.reply(403)
        super().do_GET()

    def do_PUT(self):
        matched = re.fullmatch(PREFIX + f"({ID})/(pack|context|loss)", self.path)
        if not matched:
            return self.reply(404)
        attempt, field = matched.groups()
        if not self.permitted({"pack": "sender", "context": "registrar", "loss": "recovery"}[field], attempt):
            return self.reply(403)
        if field == "pack":
            return super().do_PUT()
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch("[0-9]{1,10}", lengths[0]):
            return self.reply(411)
        size = int(lengths[0])
        if size > 2 * (TRUST_LIMIT + CHALLENGE_LIMIT):
            return self.reply(413)
        try:
            raw = self.rfile.read(size)
            if len(raw) != size:
                return self.reply(400)
            if field == "loss":
                reason = json.loads(raw)["reason"]
                if not isinstance(reason, str) or not re.fullmatch("[a-z][a-z0-9_]{0,63}", reason):
                    return self.reply(400)
                self.server.store.mark_missing(attempt, reason)
            else:
                data = json.loads(raw)
                trust, challenge = (base64.b64decode(data[k], validate=True) for k in ("trust", "challenge"))
                if (not 0 < len(trust) <= TRUST_LIMIT or not 0 < len(challenge) <= CHALLENGE_LIMIT
                        or json.loads(trust)["admission"]["attempt_id"] != attempt):
                    return self.reply(400)
                self.server.store.register(trust, challenge)
        except (TypeError, KeyError, ValueError, RecursionError):
            return self.reply(400)
        except Conflict:
            return self.reply(409)
        self.reply(200, encode({"attempt_id": attempt}))


class PrivateServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.settimeout(5)
            return self.context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


def service(config, store, signer, verifier):
    options = json.loads(Path(config).read_bytes())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(options["cert"], options["key"])
    context.load_verify_locations(cafile=options["client_ca"])
    context.verify_mode = ssl.CERT_REQUIRED
    grants = options["clients"]
    for fingerprint, grant in grants.items():
        if (not re.fullmatch("[a-f0-9]{64}", fingerprint) or not isinstance(grant, dict)
                or not all(isinstance(grant.get(k, []), list) for k in ("roles", "attempts", "prefixes"))
                or not set(grant["roles"]) <= {"registrar", "sender", "reader", "relay", "recovery"}
                or not all(re.fullmatch(ID, value) for value in grant.get("attempts", []) + grant.get("prefixes", []))):
            raise ValueError("invalid client grant")
    server = PrivateServer((options["host"], options["port"]), PrivateHandler)
    server.context, server.grants = context, grants
    server.store, server.signer, server.verify = store, signer, verifier
    return server
