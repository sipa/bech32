// Copyright (c) 2020 J.K. Zhou
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'segwit_addr.dart';

String test_encode(String hrp, int witVer, String hexWitProg) {
  return encode(hrp, witVer, hex.decode(hexWitProg));
}

List<dynamic> test_decode(String hrp, String addr) {
  var ret = decode(hrp, addr);
  var witVer = ret[0] as int;
  var witData = ret[1] as List<int>;
  return [witVer, hex.encode(witData)];
}

void main() {
  test('test encode valid', () {
      expect(
        test_encode('bc', 0, '751e76e8199196d454941c45d1b3a323f1433bd6'),
        'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
      expect(
        test_encode('tb', 0, '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'), 
        'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7');
      expect(
        test_encode('bc', 1, '751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'), 
        'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx');
      expect(
        test_encode('bc', 0x10, '751e'),
        'bc1sw50qa3jx3s');
      expect(
        test_encode('bc', 0x02, '751e76e8199196d454941c45d1b3a323'),
        'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj');
      expect(
        test_encode('tb', 0, '000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'),
        'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy');
  });

  test('test decode valid', () {
    expect(
      test_decode('bc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), 
      [0, '751e76e8199196d454941c45d1b3a323f1433bd6']);
    expect(
      test_decode('tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'),
      [0, '1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262']);
    expect(
      test_decode('bc', 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx'),
      [1, '751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6']);
    expect(
      test_decode('bc', 'bc1sw50qa3jx3s'),
      [0x10, '751e']);
    expect(
      test_decode('bc', 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj'),
      [0x02, '751e76e8199196d454941c45d1b3a323']);
    expect(
      test_decode('tb', 'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy'),
      [0, '000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433']);
  });

  test('test invalid checksum', () {
    expect(() => test_decode('bc', 'bc1nwldj5'), throwsException);
    expect(() => test_decode('bc', 'bc1nwldj5'), throwsException);
    expect(() => test_decode('bc', 'bc1an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx'), throwsException);
    expect(() => test_decode('bc', 'bc1pzry9x0s0muk'), throwsException);
    expect(() => test_decode('x', 'x1b4n0q5v'), throwsException);
    expect(() => test_decode('li', 'li1dgmt3'), throwsException);
  });

  test('test invalid address', () {
    expect(() => test_decode('bc', 'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty'), throwsException);
    expect(() => test_decode('bc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5'), throwsException);
    expect(() => test_decode('bc', 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2'), throwsException);
    expect(() => test_decode('bc', 'bc1rw5uspcuh'), throwsException);
    expect(() => test_decode('bc', 'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90'), throwsException);
    expect(() => test_decode('bc', 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P'), throwsException);
    expect(() => test_decode('tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7'), throwsException);
    expect(() => test_decode('bc', 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du'), throwsException);
    expect(() => test_decode('tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv'), throwsException);
    expect(() => test_decode('bc', 'bc1gmk9yu'), throwsException);
  });
}