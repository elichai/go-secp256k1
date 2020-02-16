package secp256k1

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

// TODO: Add test vectors. (even though they're included in libsecp itself)

func fastGeneratePrivateKey(t *testing.T) (key *PrivateKey) {
	buf := [32]byte{}
	for {
		n, err := rand.Read(buf[:])
		if err != nil || n != len(buf) {
			t.Fatalf("Failed generating a privatekey %v", err)
		}
		privkey, err := ParsePrivateKey(buf)
		if err == nil {
			return privkey
		}
	}
}

func TestParseSerializePrivateKey(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)

		serialized := privkey.Serialize()
		privkey2, err := ParsePrivateKey(serialized)
		if err != nil {
			t.Errorf("Failed parsing privkey %v", err)
		}

		if *privkey != *privkey2 {
			t.Errorf("Privkeys aren't equal %v %v", privkey2, privkey)
		}
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	_, err := GeneratePrivateKey()
	if err != nil {
		t.Errorf("Failed generating a privatekey %v", err)
	}
}

func TestParseSchnorrPubKey(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)
		pubkey, err := privkey.GenerateSchnorrPublicKey()
		if err != nil {
			t.Errorf("Failed Generating a pubkey: %v, privkey: %v", err, privkey)
		}
		serialized_compressed := pubkey.SerializeCompressed()
		serialized_uncompressed := pubkey.SerializeUncompressed()

		pubkeyNew1, err := ParseSchnorrPubKey(serialized_compressed[:])
		if err != nil {
			t.Errorf("Failed Parsing the compressed public key: %v, key: %v", err, pubkeyNew1)
		}
		pubkeyNew2, err := ParseSchnorrPubKey(serialized_uncompressed[:])
		if err != nil {
			t.Errorf("Failed Parsing the uncompressed public key: %v, key: %v", err, pubkeyNew2)
		}

		if *pubkey != *pubkeyNew1 || *pubkey != *pubkeyNew2 {
			t.Errorf("Pubkeys aren't the same: %v, %v, %v", pubkey, pubkeyNew1, pubkeyNew2)
		}
	}
}

func TestSignVerifyParseSchnorr(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)

		pubkey, err := privkey.GenerateSchnorrPublicKey()
		if err != nil {
			t.Errorf("Failed generating a pubkey: error: %v, privkey: %v", err, privkey)
		}
		msg := [32]byte{}
		n, err := rand.Read(msg[:])
		if err != nil || n != 32 {
			t.Errorf("Failed generating a msg %v %d", err, n)
		}
		sig1, err := privkey.SchnorrSign(msg)
		if err != nil {
			t.Errorf("Failed signing schnorr: error: %v, key: %v, msg: %v", err, privkey, msg)
		}
		sig2, err := privkey.SchnorrSign(msg)
		if err != nil {
			t.Errorf("Failed signing schnorr: error: %v, key: %v, msg: %v", err, privkey, msg)
		}
		if *sig1 != *sig2 {
			t.Errorf("Signing isn't deterministic %v %v", sig1, sig2)
		}
		serialized := sig1.Serialize()
		sigDeserialized := ParseSchnorrSignature(serialized)
		if *sig1 != sigDeserialized {
			t.Errorf("Failed Deserializing schnorr sig %v", serialized)
		}
		if !pubkey.SchnorrVerify(msg, *sig1) {
			t.Errorf("Failed verifying schnorr signature privkey: %v pubkey: %v signature: %v", privkey, pubkey, sig1)
		}
	}
}

// decodeHex decodes the passed hex string and returns the resulting bytes. It
// panics if an error occurs. This is only used in the tests as a helper since
// the only way it can fail is if there is an error in the test source code.
func decodeHex(hexStr string) []byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		panic("invalid hex string in test source: err " + err.Error() +
			", hex: " + hexStr)
	}

	return b
}

func TestSchnorrSignatureVerify(t *testing.T) {
	// Test vectors taken from https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr/test-vectors.csv
	tests := []struct {
		pubKey    []byte
		message   []byte
		signature []byte
		valid     bool
	}{
		{
			decodeHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05"),
			true,
		},
		{
			decodeHex("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			true,
		},
		{
			decodeHex("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
			decodeHex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
			decodeHex("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380"),
			true,
		},
		{
			decodeHex("03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"),
			decodeHex("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703"),
			decodeHex("00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D"),
			true,
		},
		{
			decodeHex("031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187"),
			true,
		},
		{
			decodeHex("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
			decodeHex("570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DCE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD"),
			true,
		},
		{
			decodeHex("02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7"),
			false,
		},
		{
			decodeHex("03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B"),
			decodeHex("5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"),
			decodeHex("00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC"),
			false,
		},
		{
			decodeHex("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000000"),
			decodeHex("787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("00000000000000000000000000000000000000000000000000000000000000009E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("0000000000000000000000000000000000000000000000000000000000000001D37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD"),
			false,
		},
		{
			decodeHex("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
			decodeHex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"),
			decodeHex("2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
			false,
		},
	}

	sig64 := [64]byte{}
	msg32 := [32]byte{}
	for i, test := range tests {
		pubkey, err := ParseSchnorrPubKey(test.pubKey)
		if err != nil {
			t.Fatal(err)
		}
		copy(sig64[:], test.signature)
		sig := ParseSchnorrSignature(sig64)

		copy(msg32[:], test.message)
		valid := pubkey.SchnorrVerify(msg32, sig)
		if valid != test.valid {
			t.Errorf("Schnorr test vector %d didn't produce correct result", i)
		}
	}
}

func TestDeterministicSchnorrSignatureGen(t *testing.T) {
	// Test vector from Bitcoin-ABC
	privKeyBytes := [32]byte{}
	copy(privKeyBytes[:], decodeHex("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747"))
	privKey, _ := ParsePrivateKey(privKeyBytes)

	msg := [32]byte{}
	copy(msg[:], decodeHex("5255683da567900bfd3e786ed8836a4e7763c221bf1ac20ece2a5171b9199e8a"))
	sig, err := privKey.SchnorrSign(msg)
	if err != nil {
		t.Fatal(err)
	}
	serializedSig := sig.Serialize()
	if !bytes.Equal(serializedSig[:32], decodeHex("2c56731ac2f7a7e7f11518fc7722a166b02438924ca9d8b4d111347b81d07175")) ||
		!bytes.Equal(serializedSig[32:], decodeHex("71846de67ad3d913a8fdf9d8f3f73161a4c48ae81cb183b214765feb86e255ce")) {
		t.Error("Failed to generate deterministic schnorr signature")
	}
}

func BenchmarkSchnorrVerify(b *testing.B) {
	b.ReportAllocs()
	sigs := make([]SchnorrSignature, b.N)
	msgs := make([][32]byte, b.N)
	pubkeys := make([]SchnorrPublicKey, b.N)
	for i := 0; i < b.N; i++ {
		msg := [32]byte{}
		n, err := rand.Read(msg[:])
		if err != nil || n != 32 {
			panic("benchmark failed")
		}
		privkey, err := GeneratePrivateKey()
		if err != nil {
			panic("benchmark failed")
		}
		sigTmp, err := privkey.SchnorrSign(msg)
		if err != nil {
			panic("benchmark failed")
		}
		sigs[i] = *sigTmp
		pubkeyTmp, err := privkey.GenerateSchnorrPublicKey()
		if err != nil {
			panic("benchmark failed")
		}
		pubkeys[i] = *pubkeyTmp
		msgs[i] = msg
	}
	b.ResetTimer()
	sum := 0
	for i := 0; i < b.N; i++ {
		ret := pubkeys[i].SchnorrVerify(msgs[i], sigs[i])
		if ret {
			sum += 1
		}
	}
	if sum != b.N { // To prevent optimizing out the loop
		panic("bad benchmark")
	}
}
