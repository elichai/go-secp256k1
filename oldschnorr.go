package secp256k1

// #include "./depend/secp256k1/include/secp256k1_oldschnorr.h"
import "C"
import "errors"

type SchnorrPublicKey struct {
	pubkey C.secp256k1_pubkey
}

type SchnorrSignature struct {
	sig [64]byte
}

func (signature *SchnorrSignature) Serialize() [64]byte {
	return signature.sig
}

func ParseSchnorrSignature(serialized [64]byte) SchnorrSignature {
	signature := SchnorrSignature{}
	signature.sig = serialized
	return signature
}

func (key *PrivateKey) GenerateSchnorrPublicKey() (*SchnorrPublicKey, error) {
	pubkey := SchnorrPublicKey{}
	cPtrPrivKey := (*C.uchar)(&key.privkey[0])
	ret := C.secp256k1_ec_pubkey_create(context, &pubkey.pubkey, cPtrPrivKey)
	if ret != 1 {
		return nil, errors.New("failed Generating an OldSchnorrPublicKey. You should call `ParsePrivateKey` before calling this")
	}
	return &pubkey, nil
}

func (key *PrivateKey) SchnorrSign(hash [32]byte) (*SchnorrSignature, error) {
	signature := SchnorrSignature{}
	cPtrSig := (*C.uchar)(&signature.sig[0])
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrPrivKey := (*C.uchar)(&key.privkey[0])
	ret := C.secp256k1_schnorr_sign(context, cPtrSig, cPtrHash, cPtrPrivKey, nil, nil)
	if ret != 1 {
		return nil, errors.New("failed Signing ECDSA. You should call `ParsePrivateKey` before calling this")
	}
	return &signature, nil
}

func (key *SchnorrPublicKey) SchnorrVerify(hash [32]byte, signature SchnorrSignature) bool {
	cPtrHash := (*C.uchar)(&hash[0])
	cPtrSig := (*C.uchar)(&signature.sig[0])
	return C.secp256k1_schnorr_verify(context, cPtrSig, cPtrHash, &key.pubkey) == 1
}

func ParseSchnorrPubKey(serialized []byte) (*SchnorrPublicKey, error) {
	key := SchnorrPublicKey{}
	cPtr := (*C.uchar)(&serialized[0])
	cLen := C.size_t(len(serialized))
	if !supportedKey(serialized) {
		return nil, errors.New("Unsupported SchnorrPublicKey")
	}
	ret := C.secp256k1_ec_pubkey_parse(C.secp256k1_context_no_precomp, &key.pubkey, cPtr, cLen)
	if ret != 1 {
		return nil, errors.New("failed parsing the SchnorrPublicKey")
	}
	return &key, nil
}

func (key *SchnorrPublicKey) SerializeCompressed() [33]byte {
	serialized := [33]byte{}
	key.serializeInternal(serialized[:], C.SECP256K1_EC_COMPRESSED)
	return serialized
}

func (key *SchnorrPublicKey) SerializeUncompressed() [65]byte {
	serialized := [65]byte{}
	key.serializeInternal(serialized[:], C.SECP256K1_EC_UNCOMPRESSED)
	return serialized
}

// TODO: Add tests
func (key *SchnorrPublicKey) Add(tweak [32]byte) error {
	cPtrTweak := (*C.uchar)(&tweak[0])
	ret := C.secp256k1_ec_pubkey_tweak_add(C.secp256k1_context_no_precomp, &key.pubkey, cPtrTweak)
	if ret != 1 {
		return errors.New("failed adding to the public key. tweak is bigger than the order or the complement of the private key")
	}
	return nil
}

// Should only be called with 33/65 byte data slice and only with SECP256K1_EC_UNCOMPRESSED/SECP256K1_EC_COMPRESSED as flags.
func (key *SchnorrPublicKey) serializeInternal(data []byte, flag C.uint) error {
	cPtr := (*C.uchar)(&data[0])
	cLen := C.size_t(len(data))

	ret := C.secp256k1_ec_pubkey_serialize(C.secp256k1_context_no_precomp, cPtr, &cLen, &key.pubkey, flag)
	if ret != 1 {
		return errors.New("failed serializing SchnorrPublicKey. should never happen")
	} else if cLen != C.size_t(len(data)) {
		panic("Returned length doesn't match the required length, something is bad")
	}
	return nil
}

func supportedKey(key []byte) bool {
	if len(key) == 33 && (key[0] == 0x02 || key[0] == 0x03) {
		return true
	} else if len(key) == 65 && key[0] == 0x04 {
		return true
	} else {
		return false
	}
}
