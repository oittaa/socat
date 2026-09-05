"""Regenerate schedule.json using Python's independent HMAC implementation.

The synthetic transcripts exercise HKDF and transcript framing, not message
validation. Real handshakes are checked separately against independent peers.
"""

import hashlib
import hmac
import json
from pathlib import Path


def vector(name):
    digest = getattr(hashlib, name)
    size = digest().digest_size

    def mac(key, value):
        return hmac.digest(key, value, name)

    def expand(secret, label, context):
        label = b"dtls13" + label
        info = size.to_bytes(2, "big") + bytes([len(label)]) + label
        info += bytes([len(context)]) + context
        return mac(secret, info + b"\x01")

    def message(kind, body):
        return bytes([kind]) + len(body).to_bytes(3, "big") + body

    shared = bytes(range(32))
    first_hello = message(1, b"first client hello")
    retry = message(2, b"retry cookie")
    second_hello = message(1, b"second client hello")
    hello = message(1, b"client hello") + message(2, b"server hello")
    empty_hash = digest().digest()
    early = mac(bytes(size), bytes(size))
    handshake = mac(expand(early, b"derived", empty_hash), shared)
    master = mac(expand(handshake, b"derived", empty_hash), bytes(size))
    client_handshake = expand(handshake, b"c hs traffic", digest(hello).digest())
    server_handshake = expand(handshake, b"s hs traffic", digest(hello).digest())
    transcript = hello + message(8, b"extensions") + message(11, b"certificate")
    transcript += message(15, b"certificate verify")
    server_finished = mac(expand(server_handshake, b"finished", b""), digest(transcript).digest())
    transcript += message(20, server_finished)
    client_finished = mac(expand(client_handshake, b"finished", b""), digest(transcript).digest())
    client_application = expand(master, b"c ap traffic", digest(transcript).digest())
    server_application = expand(master, b"s ap traffic", digest(transcript).digest())
    result = {
        "shared": shared, "hello": hello, "master": master,
        "client_handshake": client_handshake, "server_handshake": server_handshake,
        "server_finished": server_finished, "client_finished": client_finished,
        "client_application": client_application, "server_application": server_application,
        "client_update": expand(client_application, b"traffic upd", b""),
        "retry_transcript": message(254, digest(first_hello).digest()) + retry + second_hello,
    }
    return {key: value.hex() for key, value in result.items()}


if __name__ == "__main__":
    Path(__file__).with_suffix(".json").write_text(
        json.dumps({name: vector(name) for name in ("sha256", "sha384")}, indent=2) + "\n",
        encoding="utf-8",
    )
