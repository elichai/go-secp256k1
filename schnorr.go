package secp256k1

// #include "./depend/secp256k1/include/secp256k1_schnorrsig.h"
import "C"
import "errors"

type SchnorrPublicKey struct {
	pubkey C.secp256k1_xonly_pubkey
}

type SchnorrSignature struct {
	sig C.secp256k1_schnorrsig
}

func (key *PrivateKey) GenerateSchnorrPublicKey() SchnorrPublicKey {
	pubkey := SchnorrPublicKey{}
	cPtrPrivKey := (*C.uchar)(&key.privkey[0])
	ret := C.secp256k1_xonly_pubkey_create(context, &pubkey.pubkey, cPtrPrivKey)
	if ret != 1 {
		panic("failed Generating an SchnorrPublicKey. should never happen")
	}
	return pubkey
}

func (key *PrivateKey) SchnorrSign(hash [32]byte) SchnorrSignature {
	signature := SchnorrSignature{}
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrPrivKey := (*C.uchar)(&key.privkey[0])
	ret := C.secp256k1_schnorrsig_sign(context, &signature.sig, cPtrHash, cPtrPrivKey, nil, nil)
	if ret != 1 {
		panic("failed Signing ECDSA. should never happen")
	}
	return signature
}

func ParseSchnorrPubKey(serialized [32]byte) (key *SchnorrPublicKey, err error) {
	key = &SchnorrPublicKey{}
	cPtr := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_xonly_pubkey_parse(C.secp256k1_context_no_precomp, &key.pubkey, cPtr)
	if ret != 1 {
		return nil, errors.New("failed parsing the SchnorrPublicKey")
	}
	return
}

func (key *SchnorrPublicKey) SchnorrVerify(hash [32]byte, signature SchnorrSignature) bool {
	cPtrHash := (*C.uchar)(&hash[0])
	return C.secp256k1_schnorrsig_verify(context, &signature.sig, cPtrHash, &key.pubkey) == 1
}

func (key *SchnorrPublicKey) Serialize() [32]byte {
	serialized := [32]byte{}
	cPtr := (*C.uchar)(&serialized[0])

	ret := C.secp256k1_xonly_pubkey_serialize(C.secp256k1_context_no_precomp, cPtr, &key.pubkey)
	if ret != 1 {
		panic("failed serializing SchnorrPublicKey. should never happen")
	}
	return serialized
}
