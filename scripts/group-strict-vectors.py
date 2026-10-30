#!/usr/bin/env python3
"""Regenerate protocol/group-vectors.json["strict_payload"].

Every invalid entry carries a valid signature from a member allowed to make the
change, so it is rejected only for its ambiguous encoding. Test identities only.
"""
import base64
import hashlib
import json
import pathlib
from nacl.signing import SigningKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
PATH = ROOT / 'protocol/group-vectors.json'
DOMAIN = b'common-relay/group-signing/v1\0'
def key(byte): return SigningKey(hashlib.sha256(DOMAIN + bytes([byte]) * 32).digest())
MAC, PHONE, DELEGATE = key(1), key(2), key(0x71)

def entry(raw, signer, device):
    return {'payload': base64.b64encode(raw).decode(), 'signature': signer.sign(raw).signature.hex(), 'signer': device}

def main():
    v = json.loads(PATH.read_text())
    assert MAC.verify_key.encode().hex() == v['manager']['signing_key'] and PHONE.verify_key.encode().hex() == v['new_member']['signing_key']
    renamed = base64.b64decode(v['renamed']['payload']).decode()
    member = '"name":"我的手机"'
    phone = '"device":"phone",' + member
    assert renamed.count(phone) == 1 and renamed.count('"manager":false') == 1

    def rename(old, new, count=1):
        assert renamed.count(old) == count, old
        return entry(renamed.replace(old, new).encode(), PHONE, 'phone')

    newline = dict(v['renamed']); newline['payload'] = newline['payload'][:40] + '\n' + newline['payload'][40:]
    grant = json.loads(base64.b64decode(v['auto_admission']['grant']['payload']))
    grant_raw = json.dumps(grant, separators=(',', ':')).replace('"anchor_hash"', '"extra":1,"anchor_hash"').encode()
    auto = dict(v['auto_admission']['approved']); auto['authorization'] = entry(grant_raw, MAC, 'mac')
    assert DELEGATE.verify_key.encode().hex() == grant['delegate_key']

    v['strict_payload'] = {
        'note': 'invalid entries are signed correctly but encoded ambiguously and must be rejected; valid must be accepted. Base is approved; invalid_auto base is initial.',
        'valid': [
            {'case': 'whitespace_and_escapes', 'entry': rename(member, ' "name" : "\\u6211\\u7684\\/\\u624b\\u673a" ')},
        ],
        'invalid': [
            {'case': 'unknown_member_field', 'entry': rename(phone, phone + ',"evil":1')},
            {'case': 'case_variant_key', 'entry': rename(phone, phone + ',"Manager":true')},
            {'case': 'duplicate_key', 'entry': rename('"manager":false', '"manager":true,"manager":false')},
            {'case': 'escaped_key', 'entry': rename('"manager":false', '"m\\u0061nager":false')},
            {'case': 'unknown_state_field', 'entry': rename('"version":1,', '"version":1,"extra":"x",')},
            {'case': 'null_value', 'entry': rename('"invitation":""', '"invitation":null')},
            {'case': 'fraction_number', 'entry': rename('"revision":3', '"revision":3.0')},
            {'case': 'exponent_number', 'entry': rename('"revision":3', '"revision":3e0')},
            {'case': 'leading_zero_number', 'entry': rename('"version":1', '"version":01')},
            {'case': 'bool_as_number', 'entry': rename('"manager":false', '"manager":0')},
            {'case': 'number_as_string', 'entry': rename('"revision":3', '"revision":"3"')},
            {'case': 'missing_field', 'entry': rename(',"request_hash":""', '')},
            {'case': 'lone_surrogate', 'entry': rename(member, '"name":"\\ud800"')},
            {'case': 'trailing_data', 'entry': entry(renamed.encode() + b'{}', PHONE, 'phone')},
            {'case': 'base64_newline', 'entry': newline},
        ],
        'invalid_auto': [
            {'case': 'grant_unknown_field', 'entry': auto},
        ],
    }
    canonical = v['strict_payload']['valid'][0]['entry']
    text = canonical['payload']
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    idx = len(text.rstrip('=')) - 1
    noncanonical = text[:idx] + alphabet[alphabet.index(text[idx]) | 1] + text[idx+1:]
    for name, value in [('base64_missing_padding', text.rstrip('=')),
                        ('base64_nonzero_pad_bits', noncanonical),
                        ('base64_wrapped_valid_payload', text[:20] + '\n' + text[20:])]:
        v['strict_payload']['invalid'].append({'case': name, 'entry': {**canonical, 'payload': value}})
    PATH.write_text(json.dumps(v, ensure_ascii=False, indent=2) + '\n')

if __name__ == '__main__':
    main()
