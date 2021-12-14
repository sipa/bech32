// Copyright (c) 2017 Takatoshi Nakagawa
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
package bech32_test

import (
	"bech32"
	"reflect"
	"strings"
	"testing"
)

const (
	encBech32  = 1
	encBech32m = 2
)

var encoding = []int{encBech32, encBech32m}

func segwitScriptpubkey(version int, program []int) []int {
	if version != 0 {
		version += 0x50
	}
	return append(append([]int{version}, len(program)), program...)
}

var validBech32 = []string{
	"A12UEL5L",
	"a12uel5l",
	"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
	"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
	"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
	"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	"?1ezyfcl",
}

var validBech32m = []string{
	"A1LQFN3A",
	"a1lqfn3a",
	"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
	"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
	"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
	"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
	"?1v759aa",
}

var invalidBech32 = []string{
	" 1nwldj5",         // HRP character out of range
	"\x7F" + "1axkwrx", // HRP character out of range
	"\x80" + "1eym55h", // HRP character out of range
	// overall max length exceeded
	"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
	"pzry9x0s0muk",      // No separator character
	"1pzry9x0s0muk",     // Empty HRP
	"x1b4n0q5v",         // Invalid data character
	"li1dgmt3",          // Too short checksum
	"de1lg7wt" + "\xFF", // Invalid character in checksum
	"A1G7SGD8",          // checksum calculated with uppercase form of HRP
	"10a06t8",           // empty HRP
	"1qzzfhee",          // empty HRP
}

var invalidBech32m = []string{
	" 1xj0phk",         // HRP character out of range
	"\x7F" + "1g6xzxy", // HRP character out of range
	"\x80" + "1vctc34", // HRP character out of range
	// overall max length exceeded
	"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
	"qyrz8wqd2c9m",  // No separator character
	"1qyrz8wqd2c9m", // Empty HRP
	"y1b0jsk6g",     // Invalid data character
	"lt1igcx5c0",    // Invalid data character
	"in1muywd",      // Too short checksum
	"mm1crxm3i",     // Invalid character in checksum
	"au1s5cgom",     // Invalid character in checksum
	"M1VUXWEZ",      // Checksum calculated with uppercase form of HRP
	"16plkw9",       // Empty HRP
	"1p2gdwpf",      // Empty HRP
}

type item struct {
	address      string
	scriptpubkey []int
}

var validAddress = []item{
	item{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
		[]int{
			0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
			0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
		},
	},
	item{"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		[]int{
			0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
			0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
			0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
			0x62,
		},
	},
	item{"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
		[]int{
			0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
			0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
			0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
			0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
		},
	},
	item{"BC1SW50QGDZ25J",
		[]int{
			0x60, 0x02, 0x75, 0x1e,
		},
	},
	item{"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
		[]int{
			0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
			0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23,
		},
	},
	item{"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
		[]int{
			0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
			0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
			0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
			0x33,
		},
	},
}

var invalidAddress = []string{
	// Invalid HRP
	"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
	// Invalid checksum algorithm (bech32 instead of bech32m)
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
	// Invalid checksum algorithm (bech32 instead of bech32m)
	"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
	// Invalid checksum algorithm (bech32 instead of bech32m)
	"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
	// Invalid checksum algorithm (bech32m instead of bech32)
	"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
	// Invalid checksum algorithm (bech32m instead of bech32)
	"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
	// Invalid character in checksum
	"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
	// Invalid witness version
	"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
	// Invalid program length (1 byte)
	"bc1pw5dgrnzv",
	// Invalid program length (41 bytes)
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
	// Invalid program length for witness version 0 (per BIP141)
	"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
	// Mixed case
	"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
	// More than 4 padding bits
	"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
	// Non-zero padding in 8-to-5 conversion
	"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
	// Empty data section
	"bc1gmk9yu",
}

func TestValidChecksum(t *testing.T) {
	var tests []string
	for _, spec := range encoding {
		if spec == encBech32 {
			tests = validBech32
		} else {
			tests = validBech32m
		}

		for _, test := range tests {
			hrp, data, spec, err := bech32.Decode(test)
			if err != nil {
				t.Errorf("Valid checksum for %s : FAIL / error %+v\n", test, err)
			} else {
				t.Logf("Valid checksum for %s : ok / hrp : %+v , data : %+v, spec : %+v\n", test, hrp, data, spec)
			}
		}
	}
}

func TestInvalidChecksum(t *testing.T) {
	var tests []string
	for _, spec := range encoding {
		if spec == encBech32 {
			tests = validBech32
		} else {
			tests = validBech32m
		}

		for _, test := range tests {
			hrp, data, spec, err := bech32.Decode(test)
			if err != nil {
				t.Errorf("Invalid checksum for %s : ok / hrp : %+v , data : %+v, spec : %+v\n", test, hrp, data, spec)
			} else {
				t.Logf("Invalid checksum for %s : FAIL\n", test)
			}
		}
	}
}

func TestValidAddress(t *testing.T) {
	for _, test := range validAddress {
		hrp := "bc"
		version, program, err := bech32.SegwitAddrDecode(hrp, test.address)
		if err != nil {
			hrp = "tb"
			version, program, err = bech32.SegwitAddrDecode(hrp, test.address)
		}
		ok := err == nil
		if ok {
			output := segwitScriptpubkey(version, program)
			ok = reflect.DeepEqual(output, test.scriptpubkey)
		}
		if ok {
			recreate, err := bech32.SegwitAddrEncode(hrp, version, program)
			if err == nil {
				ok = recreate == strings.ToLower(test.address)
			}
		}
		if ok {
			t.Logf("Valid address %v : ok\n", test.address)
		} else {
			t.Errorf("Valid address %v : FAIL\n", test.address)
		}
	}
}

func TestInvalidAddress(t *testing.T) {
	for _, test := range invalidAddress {
		_, _, bcErr := bech32.SegwitAddrDecode("bc", test)
		t.Logf("bc error:%v\n", bcErr)
		_, _, tbErr := bech32.SegwitAddrDecode("tb", test)
		t.Logf("tb error:%v\n", tbErr)
		if bcErr != nil && tbErr != nil {
			t.Logf("Invalid address %v : ok\n", test)
		} else {
			t.Errorf("Invalid address %v : FAIL\n", test)
		}
	}
}

// add coverage tests

func TestCoverage(t *testing.T) {
	var err error
	var bech32String string
	var hrp string
	var data []int

	// SegwitAddrEncode
	bech32String, err = bech32.SegwitAddrEncode("bc", 1, []int{0, 1})
	if err != nil {
		t.Errorf("Coverage SegwitAddrEncode normal case : FAIL / error : %+v\n", err)
	} else {
		t.Log("Coverage SegwitAddrEncode normal case : ok / bech32String :", bech32String)
	}
	data = make([]int, 40)
	bech32String, err = bech32.SegwitAddrEncode("bc", 16, data)
	if err != nil {
		t.Errorf("Coverage SegwitAddrEncode normal case : FAIL / error : %+v\n", err)
	} else {
		t.Log("Coverage SegwitAddrEncode normal case : ok / bech32String :", bech32String)
	}
	data = make([]int, 20)
	bech32String, err = bech32.SegwitAddrEncode("bc", 0, data)
	if err != nil {
		t.Errorf("Coverage SegwitAddrEncode normal case : FAIL / error : %+v\n", err)
	} else {
		t.Log("Coverage SegwitAddrEncode normal case : ok / bech32String :", bech32String)
	}
	data = make([]int, 32)
	bech32String, err = bech32.SegwitAddrEncode("bc", 0, data)
	if err != nil {
		t.Errorf("Coverage SegwitAddrEncode normal case : FAIL / error : %+v\n", err)
	} else {
		t.Log("Coverage SegwitAddrEncode normal case : ok / bech32String :", bech32String)
	}
	data = make([]int, 1)
	_, err = bech32.SegwitAddrEncode("bc", 1, data)
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode invalid program length error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode invalid program length error case : ok / error :", err)
	}
	data = make([]int, 41)
	_, err = bech32.SegwitAddrEncode("bc", 1, data)
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode invalid program length error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode invalid program length error case : ok / error :", err)
	}
	data = make([]int, 26)
	_, err = bech32.SegwitAddrEncode("bc", 0, data)
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode invalid program length for witness version 0 (per BIP141) error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode invalid program length for witness version 0 (per BIP141) error case : ok / error :", err)
	}
	data = make([]int, 20)
	_, err = bech32.SegwitAddrEncode("Bc", 0, data)
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode Encode error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode Encode error case : ok / error :", err)
	}
	_, err = bech32.SegwitAddrEncode("bc", 1, []int{-1, 0})
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode invalid data range error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode invalid data range error case : ok / error :", err)
	}
	_, err = bech32.SegwitAddrEncode("bc", -1, data)
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode invalid witness version error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode invalid witness version error case : ok / error :", err)
	}
	_, err = bech32.SegwitAddrEncode("bc", 17, data)
	if err == nil {
		t.Errorf("Coverage SegwitAddrEncode invalid witness version error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrEncode invalid witness version error case : ok / error :", err)
	}

	// SegwitAddrDecode
	_, _, err = bech32.SegwitAddrDecode("a", "A12UEL5L")
	if err == nil {
		t.Errorf("Coverage SegwitAddrDecode invalid decode data length error case : FAIL")
	} else {
		t.Log("Coverage SegwitAddrDecode invalid decode data length error case : ok / error :", err)
	}

	// Decode
	_, _, _, err = bech32.Decode("!~1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc356v3")
	if err != nil {
		t.Errorf("Coverage Decode normal case : FAIL / error :%v", err)
	} else {
		t.Log("Coverage Decode normal case : ok")
	}
	_, _, _, err = bech32.Decode("a1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	if err == nil {
		t.Errorf("Coverage Decode too long error case : FAIL")
	} else {
		t.Log("Coverage Decode too long error case : ok / error :", err)
	}
	_, _, _, err = bech32.Decode("1")
	if err == nil {
		t.Errorf("Coverage Decode separator '1' at invalid position error case : FAIL")
	} else {
		t.Log("Coverage Decode separator '1' at invalid position error case : ok / error :", err)
	}
	_, _, _, err = bech32.Decode("a1qqqqq")
	if err == nil {
		t.Errorf("Coverage Decode separator '1' at invalid position error case : FAIL")
	} else {
		t.Log("Coverage Decode separator '1' at invalid position error case : ok / error :", err)
	}
	_, _, _, err = bech32.Decode("a" + string(rune(32)) + "1qqqqqq")
	if err == nil {
		t.Errorf("Coverage Decode invalid character human-readable part error case : FAIL")
	} else {
		t.Log("Coverage Decode invalid character human-readable part error case : ok / error :", err)
	}
	_, _, _, err = bech32.Decode("a" + string(rune(127)) + "1qqqqqq")
	if err == nil {
		t.Errorf("Coverage Decode invalid character human-readable part error case : FAIL")
	} else {
		t.Log("Coverage Decode invalid character human-readable part error case : ok / error :", err)
	}
	_, _, _, err = bech32.Decode("a1qqqqqb")
	if err == nil {
		t.Errorf("Coverage Decode invalid character data part error case : FAIL")
	} else {
		t.Log("Coverage Decode invalid character data part erroer case : ok / error :", err)
	}

	// Encode
	hrp = "bc"
	data = []int{}
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err != nil || bech32String != strings.ToLower(bech32String) {
		t.Errorf("Coverage Encode lower case : FAIL / bech32String : %v , error : %v", bech32String, err)
	} else {
		t.Log("Coverage Encode lower case : ok / bech32String : ", bech32String)
	}
	hrp = "BC"
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err != nil || bech32String != strings.ToUpper(bech32String) {
		t.Errorf("Coverage Encode upper case : FAIL / bech32String : %v , error : %v", bech32String, err)
	} else {
		t.Log("Coverage Encode upper case : ok / bech32String : ", bech32String)
	}
	hrp = "bc"
	data = make([]int, 90-7-len(hrp)+1)
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode too long error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode too long error case : ok / error : ", err)
	}
	hrp = ""
	data = make([]int, 90-7-len(hrp))
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode invalid hrp error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode invalid hrp error case : ok / error : ", err)
	}
	hrp = "Bc"
	data = make([]int, 90-7-len(hrp))
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode mix case error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode mix case error case : ok / error : ", err)
	}
	hrp = string(rune(33)) + string(rune(126))
	data = make([]int, 90-7-len(hrp))
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err != nil {
		t.Errorf("Coverage Encode normal case : FAIL / error : %v", err)
	} else {
		t.Log("Coverage Encode normal case : ok / bech32String : ", bech32String)
	}
	hrp = string(rune(32)) + "c"
	data = make([]int, 90-7-len(hrp))
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode invalid character human-readable part error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode invalid character human-readable part error case : ok / error : ", err)
	}
	hrp = "b" + string(rune(127))
	data = make([]int, 90-7-len(hrp))
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode invalid character human-readable part error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode invalid character human-readable part error case : ok / error : ", err)
	}
	hrp = "bc"
	data = []int{0, 31}
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err != nil {
		t.Errorf("Coverage Encode normal case : FAIL / error : %v", err)
	} else {
		t.Log("Coverage Encode normal case : ok / bech32String : ", bech32String)
	}
	hrp = "bc"
	data = []int{-1}
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode invalid data error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode invalid data error case : ok / error : ", err)
	}
	hrp = "bc"
	data = []int{32}
	bech32String, err = bech32.Encode(hrp, data, encBech32)
	if err == nil {
		t.Errorf("Coverage Encode invalid data error case : FAIL / bech32String : %v", bech32String)
	} else {
		t.Log("Coverage Encode invalid data error case : ok / error : ", err)
	}
}
