package secp256k1

// #include "./depend/secp256k1/include/secp256k1.h"
import "C"
import "errors"

type EcdsaPublicKey struct {
	pubkey C.secp256k1_pubkey
}

type EcdsaSignature struct {
	sig C.secp256k1_ecdsa_signature
}

func (key *PrivateKey) GenerateEcdsaPublicKey() EcdsaPublicKey {
	pubkey := EcdsaPublicKey{}
	cPtrPrivKey := (*C.uchar)(&key.privkey[0])
	ret := C.secp256k1_ec_pubkey_create(context, &pubkey.pubkey, cPtrPrivKey)
	if ret != 1 {
		panic("failed Generating an EcdsaPublicKey. should never happen")
	}
	return pubkey
}

func (key *PrivateKey) EcdsaSign(hash [32]byte) EcdsaSignature {
	signature := EcdsaSignature{}
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrPrivKey := (*C.uchar)(&key.privkey[0])
	ret := C.secp256k1_ecdsa_sign(context, &signature.sig, cPtrHash, cPtrPrivKey, nil, nil)
	if ret != 1 {
		panic("failed Signing ECDSA. should never happen")
	}
	return signature
}

func ParseEcdsaPubKey(serialized []byte) (key *EcdsaPublicKey, err error) {
	if len(serialized) == 0 {
		return nil, errors.New("called ParsePubKey with empty bytes")
	}
	key = &EcdsaPublicKey{}
	cPtr := (*C.uchar)(&serialized[0])
	cLen := C.size_t(len(serialized))
	ret := C.secp256k1_ec_pubkey_parse(C.secp256k1_context_no_precomp, &key.pubkey, cPtr, cLen)
	if ret != 1 {
		return nil, errors.New("failed parsing the EcdsaPublicKey")
	}
	return
}

func (key *EcdsaPublicKey) EcdsaVerify(hash [32]byte, signature EcdsaSignature) bool {
	cPtrHash := (*C.uchar)(&hash[0])
	return C.secp256k1_ecdsa_verify(context, &signature.sig, cPtrHash, &key.pubkey) == 1
}

func (key *EcdsaPublicKey) Serialize() [33]byte {
	serialized := [33]byte{}
	cPtr := (*C.uchar)(&serialized[0])
	cLen := C.size_t(len(serialized))

	ret := C.secp256k1_ec_pubkey_serialize(C.secp256k1_context_no_precomp, cPtr, &cLen, &key.pubkey, C.SECP256K1_EC_COMPRESSED)
	if ret != 1 || cLen != 33 {
		panic("failed serializing EcdsaPublicKey. should never happen")
	}
	return serialized
}
