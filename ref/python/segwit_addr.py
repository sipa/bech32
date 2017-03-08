"""Reference implementation for Bech32 and segwit addresses."""


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def bech32_decode(bech_string):
    """Validate a Bech32 string, and determine HRP and data."""
    if any(ord(x) < 31 or ord(x) > 127 for x in bech_string):
        return (None, None)
    pos = bech_string.rfind('1')
    if pos < 1 or pos + 7 > len(bech_string) or len(bech_string) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech_string[pos+1:]):
        return (None, None)
    hrp = bech_string[:pos]
    data = [CHARSET.find(x) for x in bech_string[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(testnet, witver, witprog):
    """Encode a segwit address."""
    hrp = "tb" if testnet else "bc"
    return bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))


def decode(testnet, addr):
    """Decode a segwit address."""
    hrpexp = "tb" if testnet else "bc"
    hrp, data = bech32_decode(addr.lower())
    if ((any(ord(x) < 31 or ord(x) > 127 for x in addr)) or
            (addr.lower() != addr and addr.upper() != addr) or
            hrp != hrpexp):
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    return (data[0], decoded)
