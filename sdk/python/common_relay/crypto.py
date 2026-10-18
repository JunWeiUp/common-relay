"""Shared v1 encrypted envelopes. Peer keys MUST be pinned out of band."""
import base64
import json
import struct
from nacl.public import PrivateKey, PublicKey, Box
from nacl import bindings as sodium

def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def context(app, group, sender, recipient, kind, object_id):
    # An array avoids differences in JSON object key ordering across languages.
    return [1, app, group, sender, recipient, kind, object_id]

class Identity:
    def __init__(self, app, group, device, secret_key, trusted_peers):
        self.app, self.group, self.device = app, group, device
        self.key = PrivateKey(bytes.fromhex(secret_key))
        self.trusted = {name: PublicKey(bytes.fromhex(key)) for name, key in trusted_peers.items()}

    @property
    def public_key(self):
        return bytes(self.key.public_key).hex()

    def seal(self, recipient, kind, object_id, value):
        box = Box(self.key, self.trusted[recipient])
        plain = encode({'context': context(self.app, self.group, self.device, recipient, kind, object_id), 'value': value})
        return base64.b64encode(bytes(box.encrypt(plain))).decode()

    def open(self, sender, kind, object_id, body):
        raw = base64.b64decode(body, validate=True)
        plain = Box(self.key, self.trusted[sender]).decrypt(raw)
        value = json.loads(plain)
        if value['context'] != context(self.app, self.group, sender, self.device, kind, object_id):
            raise ValueError('Authenticated context mismatch')
        return value['value']

class EncryptStream:
    def __init__(self):
        self.key = sodium.crypto_secretstream_xchacha20poly1305_keygen()
        self.state = sodium.crypto_secretstream_xchacha20poly1305_state()
        self.header = sodium.crypto_secretstream_xchacha20poly1305_init_push(self.state, self.key)
        self.finished = False

    def descriptor(self):
        return {'key': self.key.hex(), 'header': self.header.hex()}

    def push(self, data, aad, final=False):
        if self.finished:
            raise ValueError('Stream already finished')
        tag = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL if final else sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        cipher = sodium.crypto_secretstream_xchacha20poly1305_push(self.state, data, aad, tag)
        self.finished = final
        return cipher

class DecryptStream:
    def __init__(self, descriptor):
        self.state = sodium.crypto_secretstream_xchacha20poly1305_state()
        sodium.crypto_secretstream_xchacha20poly1305_init_pull(self.state, bytes.fromhex(descriptor['header']), bytes.fromhex(descriptor['key']))
        self.finished = False

    def pull(self, cipher, aad):
        if self.finished:
            raise ValueError('Data after final record')
        plain, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(self.state, cipher, aad)
        if tag not in (sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL):
            raise ValueError('Unsupported stream tag')
        self.finished = tag == sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        return plain

def stream_aad(identity, sender, recipient, object_id, sequence, kind='stream'):
    return encode(context(identity.app, identity.group, sender, recipient, kind, object_id) + [sequence])

def frame(object_id, sequence, ciphertext):
    if len(ciphertext) > 65536:
        raise ValueError('Record too large')
    return b'\x01' + bytes.fromhex(object_id) + struct.pack('>Q', sequence) + ciphertext
