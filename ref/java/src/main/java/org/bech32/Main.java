package org.bech32;

import java.util.Arrays;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.codec.binary.Hex;

public class Main {

    // test vectors
    private static String[] VALID_CHECKSUM = {
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
    };

    private static String[][] VALID_ADDRESS = {
            // example provided in BIP
            new String[] { "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            // test vectors
            new String[] { "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"},
            new String[] { "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7","00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"},
            new String[] { "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", "8128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"},
            new String[] { "BC1SW50QA3JX3S", "9002751e"},
            new String[] { "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", "8210751e76e8199196d454941c45d1b3a323"},
            new String[] { "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"},
            // BIP49 test vector
            new String[] { "tb1q8zt37uunpakpg8vh0tz06jnj0jz5jddn5mlts3", "001438971f73930f6c141d977ac4fd4a727c854935b3"},
    };

    // test vectors
    private static String[] INVALID_ADDRESS = {
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",                     // bad checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            "bc1rw5uspcuh",
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // mixed case
            "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    };

    public static void main(String[] args) {

        try {

            Pair<byte[], byte[]> p = null;

            System.out.println("checksum test");
            for(String s : VALID_CHECKSUM)   {

                p = null;

                try{
                  p = Bech32.bech32Decode(s);
                  assert(p.getLeft() != null);
                }
                catch(Exception e) {
                  System.out.println("Error:" + s + "," + e.getMessage());
                }
            }

            System.out.println("valid address test");
            for(String[] s : VALID_ADDRESS)   {
                p = null;

                try{
                  p = Bech32.bech32Decode(s[0]);
                }
                catch(Exception e) {
                  System.out.println("Error:" + s[0] + "," + e.getMessage());
                }
            }

            System.out.println("invalid address test");
            for(String s : INVALID_ADDRESS)   {

                p = null;
                Pair<Byte, byte[]> pair = null;

                try {
                  p = Bech32.bech32Decode(s);
                  pair = SegwitAddress.decode(new String(p.getLeft()), s);
                }
                catch(Exception e) {
                  ;
                }

                assert(p == null || pair == null);

            }

            System.out.println("valid segwit address test");
            for(String[] s : VALID_ADDRESS)   {
                try {
                  byte witVer;
                  String hrp = new String(Bech32.bech32Decode(s[0]).getLeft());

                  byte[] witProg;
                  Pair<Byte, byte[]> segp = null;
                  segp = SegwitAddress.decode(hrp, s[0]);
                  witVer = segp.getLeft();
                  witProg = segp.getRight();

                  assert(!(witVer < 0 || witVer > 16));

                  byte[] pubkey = SegwitAddress.getScriptPubkey(witVer, witProg);
                  assert(Hex.encodeHexString(pubkey).equalsIgnoreCase(s[1]));

                  String address = SegwitAddress.encode(hrp.getBytes(), witVer, witProg);
                  assert(s[0].equalsIgnoreCase(address));

                  int idx = s[0].lastIndexOf("1");
                  Pair<Byte, byte[]> testPair = null;
                  try{
                    testPair = SegwitAddress.decode(hrp, s[0].substring(0, idx + 1) + new String(new char[] { (char)(s[0].charAt(idx + 1) ^ 1) }) + s[0].substring(idx + 2));
                    assert(!Arrays.equals(witProg, testPair.getRight()));
                  }
                  catch(Exception e) {
                      ;
                  }
                  assert(testPair == null);

                }
                catch(Exception e) {
                  System.out.println("Error:" + s[0] + "," + e.getMessage());
                }

            }

            System.out.println("invalid segwit address test");
            for(String s : INVALID_ADDRESS)   {

              Pair<Byte, byte[]> segp = null;

                try {
                  byte witVer;
                  String hrp = new String(Bech32.bech32Decode(s).getLeft());

                  segp = SegwitAddress.decode(new String(hrp), s);
                }
                catch(Exception e) {
                  ;
                }

                assert(segp == null);

            }

        }
        catch(Exception e) {
            e.printStackTrace();
        }

        System.out.println("encode BIP49 test vector");
        try {

          Hex hex = new Hex();

          String address = SegwitAddress.encode("tb".getBytes(), (byte)0x00, hex.decode("38971f73930f6c141d977ac4fd4a727c854935b3".getBytes()));
          System.out.println("BIP49 test vector:" + address);

          byte witVer;
          String hrp = new String(Bech32.bech32Decode(address).getLeft());

          byte[] witProg;
          Pair<Byte, byte[]> segp = null;
          segp = SegwitAddress.decode(hrp, address);
          witVer = segp.getLeft();
          witProg = segp.getRight();
          System.out.println("decoded witVer:" + witVer);
          System.out.println("decoded witProg:" + Hex.encodeHexString(witProg));

          assert(!(witVer < 0 || witVer > 16));

          byte[] pubkey = SegwitAddress.getScriptPubkey(witVer, witProg);
          System.out.println("decoded pubkey:" + Hex.encodeHexString(pubkey));
        }
        catch(Exception e) {
          System.out.println("Error:" + e.getMessage());
        }

    }

}
