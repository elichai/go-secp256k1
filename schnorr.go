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

func (signature *SchnorrSignature) Serialize() [64]byte {
	serialized := [64]byte{}
	cDataPtr := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_schnorrsig_serialize(C.secp256k1_context_no_precomp, cDataPtr, &signature.sig)
	if ret != 1 {
		panic("failed Signing ECDSA. should never happen")
	}
	return serialized
}

func ParseSchnorrSignature(serialized [64]byte) (signature *SchnorrSignature, err error) {
	signature = &SchnorrSignature{}
	cDataPtr := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_schnorrsig_parse(context, &signature.sig, cDataPtr)
	if ret != 1 {
		return nil, errors.New("failed parsing the schnorr signature")
	}
	return
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

// TODO: Add tests
func (key *SchnorrPublicKey) Add(tweak [32]byte) (is_negated *bool, err error) {
	cPtrTweak := (*C.uchar)(&tweak[0])
	cIs_negated := C.int(0)
	ret := C.secp256k1_xonly_pubkey_tweak_add(C.secp256k1_context_no_precomp, &key.pubkey, &cIs_negated, &key.pubkey, cPtrTweak)
	if ret != 1 {
		return nil, errors.New("failed adding to the public key. tweak is bigger than the order or the complement of the private key")
	}
	*is_negated = (cIs_negated > 0)
	return
}
