package secp256k1

import "testing"
import "math/rand"

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

func TestParseECDSAPubKey(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)
		pubkey := privkey.GenerateEcdsaPublicKey()
		serialized := pubkey.Serialize()

		pubkeyNew, err := ParseEcdsaPubKey(serialized[:])
		if err != nil {
			t.Errorf("Failed Parsing the public key: %v", err)
		}

		if pubkey != *pubkeyNew {
			t.Errorf("Pubkeys aren't the same: %v, %v", pubkey, pubkeyNew)
		}

	}
}

func TestSignVerifyParseECDSA(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)

		pubkey := privkey.GenerateEcdsaPublicKey()
		msg := [32]byte{}
		n, err := rand.Read(msg[:])
		if err != nil || n != 32 {
			t.Fatalf("Failed generating a msg %v %d", err, n)
		}
		sig1 := privkey.EcdsaSign(msg)
		sig2 := privkey.EcdsaSign(msg)
		if sig1 != sig2 {
			t.Errorf("Signing isn't deterministic %v %v", sig1, sig2)
		}

		serialized := sig1.Serialize()
		sigDeserialized, err := ParseEcdsaSignature(serialized)
		if err != nil || sig1 != *sigDeserialized {
			t.Errorf("Failed deserializing ECDSA sig %v", serialized)
		}

		if !pubkey.EcdsaVerify(msg, sig1) {
			t.Errorf("Failed verifying ECDSA signature privkey: %v pubkey: %v signature: %v", privkey, pubkey, sig1)
		}

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
