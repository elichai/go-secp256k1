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

func TestSignVerifyECDSA(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)

		pubkey := privkey.GenerateEcdsaPublicKey()
		msg := [32]byte{}
		n, err := rand.Read(msg[:])
		if err != nil || n != 32 {
			t.Errorf("Failed generating a msg %v %d", err, n)
		}
		sig1 := privkey.EcdsaSign(msg)
		sig2 := privkey.EcdsaSign(msg)
		if sig1 != sig2 {
			t.Errorf("Signing isn't deterministic %v %v", sig1, sig2)
		}
		if !pubkey.EcdsaVerify(msg, sig1) {
			t.Errorf("Failed verifying ECDSA signature privkey: %v pubkey: %v signature: %v", privkey, pubkey, sig1)
		}

	}
}

func TestParseSchnorrPubKey(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)
		pubkey := privkey.GenerateSchnorrPublicKey()
		serialized := pubkey.Serialize()

		pubkeyNew, err := ParseSchnorrPubKey(serialized)
		if err != nil {
			t.Errorf("Failed Parsing the public key: %v", err)
		}

		if pubkey != *pubkeyNew {
			t.Errorf("Pubkeys aren't the same: %v, %v", pubkey, pubkeyNew)
		}
	}
}

func TestSignVerifySchnorr(t *testing.T) {
	for i := 0; i < 150; i++ {
		privkey := fastGeneratePrivateKey(t)

		pubkey := privkey.GenerateSchnorrPublicKey()
		msg := [32]byte{}
		n, err := rand.Read(msg[:])
		if err != nil || n != 32 {
			t.Errorf("Failed generating a msg %v %d", err, n)
		}
		sig1 := privkey.SchnorrSign(msg)
		sig2 := privkey.SchnorrSign(msg)
		if sig1 != sig2 {
			t.Errorf("Signing isn't deterministic %v %v", sig1, sig2)
		}
		if !pubkey.SchnorrVerify(msg, sig1) {
			t.Errorf("Failed verifying ECDSA signature privkey: %v pubkey: %v signature: %v", privkey, pubkey, sig1)
		}

	}
}