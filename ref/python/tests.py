#!/usr/bin/python3

import segwit_addr

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
    hrp, data = segwit_addr.bech32_decode(test)
    assert(hrp is not None)
    pos = test.rfind('1')
    test = test[:pos+1] + chr(ord(test[pos + 1]) ^ 1) + test[pos+2:]
    hrp, data = segwit_addr.bech32_decode(test)
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
    witver, witprog = segwit_addr.decode(testnet, test[0])
    if (witver is None):
      testnet = True
      witver, witprog = segwit_addr.decode(testnet, test[0])
    assert(witver is not None)
    scriptpubkey = segwit_scriptpubkey(witver, witprog)
    assert(scriptpubkey.hex() == test[1])
    addr = segwit_addr.encode(testnet, witver, witprog)
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
    witver, witprog = segwit_addr.decode(False, test)
    assert(witver is None)
    witver, witprog = segwit_addr.decode(True, test)
    assert(witver is None)
