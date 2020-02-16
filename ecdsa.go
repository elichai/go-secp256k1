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

func (signature *EcdsaSignature) Serialize() [64]byte {
	serialized := [64]byte{}
	cDataPtr := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_ecdsa_signature_serialize_compact(C.secp256k1_context_no_precomp, cDataPtr, &signature.sig)
	if ret != 1 {
		panic("failed Signing ECDSA. should never happen")
	}
	return serialized
}

func ParseEcdsaSignature(serialized [64]byte) (signature *EcdsaSignature, err error) {
	signature = &EcdsaSignature{}
	cDataPtr := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_ecdsa_signature_parse_compact(context, &signature.sig, cDataPtr)
	if ret != 1 {
		return nil, errors.New("failed parsing the ECDSA signature")
	}
	return
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

// TODO: Add tests
func (key *EcdsaPublicKey) Negate() {
	ret := C.secp256k1_ec_pubkey_negate(C.secp256k1_context_no_precomp, &key.pubkey)
	if ret != 1 {
		panic("Failed Negating the public key. should never happen")
	}
}

// TODO: Add tests
func (key *EcdsaPublicKey) Add(tweak [32]byte) error {
	cPtrTweak := (*C.uchar)(&tweak[0])
	ret := C.secp256k1_ec_pubkey_tweak_add(C.secp256k1_context_no_precomp, &key.pubkey, cPtrTweak)
	if ret != 1 {
		return errors.New("failed adding to the public key. tweak is bigger than the order or the complement of the private key")
	}
	return nil
}

// TODO: Add tests
func (key *EcdsaPublicKey) Combine(two *EcdsaPublicKey) (out *EcdsaPublicKey, err error) {
	arr := [2]*C.secp256k1_pubkey{&key.pubkey, &two.pubkey}
	cPtrArr := (**C.secp256k1_pubkey)(&arr[0])
	cLen := C.size_t(len(arr))
	out = &EcdsaPublicKey{}
	ret := C.secp256k1_ec_pubkey_combine(C.secp256k1_context_no_precomp, &out.pubkey, cPtrArr, cLen)
	if ret != 1 {
		return nil, errors.New("failed combining two public keys. resulted in infinity")
	}
	return
}
