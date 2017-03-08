#!/usr/bin/python3

import binascii

def bech32_polymod(values):
  GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  chk = 1
  for v in values:
    b = (chk >> 25)
    chk = (chk & 0x1ffffff) << 5 ^ v
    for i in range(5):
      chk ^= GEN[i] if ((b >> i) & 1) else 0
  return chk

def bech32_hrp_expand(s):
  return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32_verify_checksum(hrp, data):
  return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_create_checksum(hrp, data):
  values = bech32_hrp_expand(hrp) + data
  polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
  return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_encode(hrp, data):
  combined = data + bech32_create_checksum(hrp, data)
  return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def bech32_decode(s):
  if any (ord(x) < 31 or ord(x) > 127 for x in s):
    return (None, None)
  pos = s.rfind('1')
  if pos < 1 or pos + 7 > len(s) or len(s) > 90:
    return (None, None)
  if not all(x in CHARSET for x in s[pos+1:]):
    return (None, None)
  hrp = s[:pos]
  data = [CHARSET.find(x) for x in s[pos+1:]]
  if not bech32_verify_checksum(hrp, data):
    return (None, None)
  return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
  acc = 0
  bits = 0
  ret = []
  maxv = (1 << tobits) - 1
  for d in data:
    if d < 0 or (d >> frombits):
      return None
    acc = (acc << frombits) | d
    bits += frombits
    while (bits >= tobits):
      bits -= tobits
      ret.append((acc >> bits) & maxv)
  if (pad):
    if (bits):
      ret.append((acc << (tobits - bits)) & maxv)
  elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
    return None
  return ret

def segwit_addr_encode(testnet, witver, witprog):
  hrp = "tb" if testnet else "bc"
  assert (witver >= 0 and witver <= 16)
  return bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))

def segwit_addr_decode(testnet, addr):
  if any (ord(x) < 31 or ord(x) > 127 for x in addr):
    return (None, None)
  if (addr.lower() != addr and addr.upper() != addr):
    return (None, None)
  hrp, data = bech32_decode(addr.lower())
  hrpexp = "tb" if testnet else "bc"
  if hrp != hrpexp:
    return (None, None)
  decoded = convertbits(data[1:], 5, 8, False)
  if decoded is None or len(decoded) < 2 or len(decoded) > 40:
    return (None, None)
  if (data[0] > 16):
    return (None, None)
  if (data[0] == 0 and len(decoded) != 20 and len(decoded) != 32):
    return (None, None)
  return (data[0], decoded)

def segwit_scriptpubkey(ver, witprog):
  return bytes([ver + 0x80 if ver else 0, len(witprog)] + witprog)

if __name__ == "__main__":
  valid_checksum = [
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
  ]
  for test in valid_checksum:
    hrp, data = bech32_decode(test)
    assert(hrp is not None)
    pos = test.rfind('1')
    test = test[:pos+1] + chr(ord(test[pos + 1]) ^ 1) + test[pos+2:]
    hrp, data = bech32_decode(test)
    assert(hrp is None)

  valid_address = [
    ["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"],
    ["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["BC1SW50QA3JX3S", "9002751e"],
    ["bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "8210751e76e8199196d454941c45d1b3a323"],
    ["tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"],
  ]
  for test in valid_address:
    testnet = False
    witver, witprog = segwit_addr_decode(testnet, test[0])
    if (witver is None):
      testnet = True
      witver, witprog = segwit_addr_decode(testnet, test[0])
    assert(witver is not None)
    scriptpubkey = segwit_scriptpubkey(witver, witprog)
    assert(scriptpubkey.hex() == test[1])
    addr = segwit_addr_encode(testnet, witver, witprog)
    assert(test[0].lower() == addr)

  invalid_address = [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sI5k7",
    "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
  ]
  for test in invalid_address:
    print(test)
    witver, witprog = segwit_addr_decode(False, test)
    assert(witver is None)
    witver, witprog = segwit_addr_decode(True, test)
    assert(witver is None)
