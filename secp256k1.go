package secp256k1

// // **This is CGO's build system. yes, in comments.**
// // Including the headers and code, and defining the default macros
// #cgo CFLAGS: -I./depend/secp256k1 -I./depend/secp256k1/src/
// #cgo CFLAGS: -DSECP256K1_BUILD=1 -DECMULT_WINDOW_SIZE=15 -DUSE_ENDOMORPHISM=1  -DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_MULTISET=1
// // Consider using libgmp. these macros are set to use the slower in-project implementation of nums
// #cgo CFLAGS: -DUSE_NUM_NONE=1 -DUSE_FIELD_INV_BUILTIN=1 -DUSE_SCALAR_INV_BUILTIN=1 -DECMULT_GEN_PREC_BITS=4
// // x86_64 can use the Assembly implementation.
// #cgo amd64 CFLAGS: -DUSE_ASM_X86_64=1
// // check if 32 bit
// #cgo 386 amd64p32 arm armbe mips mipsle mips64p32 mips64p32le ppc s390 sparc CFLAGS: -DUSE_FIELD_10X26=1 -DUSE_SCALAR_8X32=1
// // check if 64 bit
// #cgo amd64 arm64 arm64be ppc64 ppc64le mips64 mips64le s390x sparc64 CFLAGS: -DUSE_FIELD_5X52=1 -DUSE_SCALAR_4X64=1 -DHAVE___INT128=1
// // check if Big Endian
// #cgo arm64be armbe mips mips64 mips64p32 ppc s390 s390x sparc sparc64 CFLAGS: -DWORDS_BIGENDIAN=1
// #include "./depend/secp256k1/include/secp256k1.h"
// #include "./depend/secp256k1/src/secp256k1.c"
import "C"

import (
	"crypto/rand"
	"errors"
)

var context *C.secp256k1_context

func init() {
	context = C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN | C.SECP256K1_CONTEXT_VERIFY)
}

type PrivateKey struct {
	privkey [32]byte
}

func ParsePrivateKey(data [32]byte) (key *PrivateKey, err error) {
	cPtr := (*C.uchar)(&data[0])

	ret := C.secp256k1_ec_seckey_verify(C.secp256k1_context_no_precomp, cPtr)
	if ret != 1 {
		return nil, errors.New("invalid PrivateKey (zero or bigger than the group order)")
	}

	return &PrivateKey{data}, nil
}

func (key PrivateKey) Serialize() [32]byte {
	return key.privkey
}

func GeneratePrivateKey() (key *PrivateKey, err error) {
	key = &PrivateKey{}
	cPtr := (*C.uchar)(&key.privkey[0])
	for {
		n, tmpErr := rand.Read(key.privkey[:])
		if tmpErr != nil || n != len(key.privkey) {
			return nil, tmpErr
		}
		ret := C.secp256k1_ec_seckey_verify(C.secp256k1_context_no_precomp, cPtr)
		if ret == 1 {
			return
		}
	}
}
