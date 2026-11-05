ACCESS_HEADER = 'Relay-Access'

def access_headers(password):
    """Return the Relay-Access header for an optional server access password, validating it."""
    if password is None: return {}
    if not isinstance(password, str) or not 8 <= len(password) <= 128 or any(not 0x21 <= ord(c) <= 0x7e for c in password):
        raise ValueError('Access password must be 8-128 printable ASCII characters without spaces')
    return {ACCESS_HEADER: password}
