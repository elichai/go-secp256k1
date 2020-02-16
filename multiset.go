package secp256k1

// #include "./depend/secp256k1/include/secp256k1_multiset.h"
import "C"
import "errors"

type MultiSet struct {
	set C.secp256k1_multiset
}

func NewMultiset() MultiSet {
	multiset := MultiSet{}
	ret := C.secp256k1_multiset_init(context, &multiset.set)
	if ret != 1 {
		panic("failed intializing a multiset. should never happen")
	}
	return multiset
}

func (multiset *MultiSet) Reset() {
	ret := C.secp256k1_multiset_init(context, &multiset.set)
	if ret != 1 {
		panic("failed intializing a multiset. should never happen")
	}
}

func (multiset *MultiSet) Add(data []byte) {
	cPtrData := (*C.uchar)(&data[0])
	CLenData := (C.size_t)(len(data))
	ret := C.secp256k1_multiset_add(context, &multiset.set, cPtrData, CLenData)
	if ret != 1 {
		panic("failed adding to the multiset. should never happen")
	}
}

func (multiset *MultiSet) Remove(data []byte) {
	cPtrData := (*C.uchar)(&data[0])
	CLenData := (C.size_t)(len(data))
	ret := C.secp256k1_multiset_remove(context, &multiset.set, cPtrData, CLenData)
	if ret != 1 {
		panic("failed removing from the multiset. should never happen")
	}
}

func (multiset *MultiSet) Combine(input MultiSet) {
	ret := C.secp256k1_multiset_combine(context, &multiset.set, &input.set)
	if ret != 1 {
		panic("failed combining 2 multisets. should never happen")
	}
}

func (multiset *MultiSet) Finalize() [32]byte {
	hash := [32]byte{}
	cPtrHash := (*C.uchar)(&hash[0])
	ret := C.secp256k1_multiset_finalize(context, cPtrHash, &multiset.set)
	if ret != 1 {
		panic("failed finalizing the multiset. should never happen")
	}
	return hash
}

func (multiset *MultiSet) Serialize() [64]byte {
	serialized := [64]byte{}
	cPtrData := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_multiset_serialize(context, cPtrData, &multiset.set)
	if ret != 1 {
		panic("failed serializing the multiset. should never happen")
	}
	return serialized
}

func ParseMultiSet(serialized [64]byte) (multiset *MultiSet, err error) {
	multiset = &MultiSet{}
	cPtrData := (*C.uchar)(&serialized[0])
	ret := C.secp256k1_multiset_parse(context, &multiset.set, cPtrData)
	if ret != 1 {
		return nil, errors.New("failed parsing the multiset")
	}
	return
}
