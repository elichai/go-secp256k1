package secp256k1

import (
	"math/rand"
	"testing"
)

func TestMultiSetAddRemove(t *testing.T) {
	list := [150][100]byte{}
	set := NewMultiset()
	set2 := set
	serializedEmpty := set.Serialize()
	for i := 0; i < 150; i++ {
		data := [100]byte{}
		n, err := rand.Read(data[:])
		if err != nil || n != len(data) {
			t.Fatalf("Failed generating random data %v %d", err, n)
		}
		set.Add(data[:])
		list[i] = data
	}
	if set.Finalize() == set2.Finalize() {
		t.Errorf("sets are the same when they should be different: set %x\n", set.Finalize())
	}

	for i := 0; i < 150; i++ {
		set.Remove(list[i][:])
	}
	if set.Finalize() != set2.Finalize() {
		t.Errorf("sets are different when they should be the same: set1: %x, set2: %x\n", set.Finalize(), set2.Finalize())
	}
	if set.Serialize() != serializedEmpty {
		t.Errorf("serialized sets are different when they should be the same: set1: %x, set2: %x\n", set.Serialize(), serializedEmpty)
	}
	parsedSet, err := ParseMultiSet(serializedEmpty)
	if err != nil {
		t.Errorf("error: '%v' happened when parsing: %v", err, serializedEmpty)
	} else if parsedSet.Finalize() != set.Finalize() {
		t.Errorf("sets are different when they should be the same: set1: %x, parsedSet: %x\n", set.Finalize(), parsedSet.Finalize())

	}
}

func BenchmarkMultiSet_Add(b *testing.B) {
	b.ReportAllocs()
	list := make([][100]byte, b.N)
	for i := 0; i < b.N; i++ {
		data := [100]byte{}
		n, err := rand.Read(data[:])
		if err != nil || n != len(data) {
			b.Fatalf("Failed generating random data %v %d", err, n)
		}
		list[i] = data
	}
	set := NewMultiset()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Add(list[i][:])
		tmpSer := set.Serialize()
		tmpSet, err := ParseMultiSet(tmpSer)
		if err != nil || tmpSet.Finalize() != set.Finalize() {
			panic("bad benchmark")
		}
	}
	if set == NewMultiset() { // To prevent optimizing out the loop
		panic("bad benchmark")
	}
}

func BenchmarkMultiSet_Remove(b *testing.B) {
	b.ReportAllocs()
	list := make([][100]byte, b.N)
	for i := 0; i < b.N; i++ {
		data := [100]byte{}
		n, err := rand.Read(data[:])
		if err != nil || n != len(data) {
			b.Fatalf("Failed generating random data %v %d", err, n)
		}
		list[i] = data
	}
	set := NewMultiset()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Remove(list[i][:])
	}
	if set == NewMultiset() { // To prevent optimizing out the loop
		panic("bad benchmark")
	}
}

func BenchmarkMultiSet_Combine(b *testing.B) {
	b.ReportAllocs()
	set := NewMultiset()
	sets := make([]MultiSet, b.N)
	for i := 0; i < b.N; i++ {
		data := [100]byte{}
		n, err := rand.Read(data[:])
		if err != nil || n != len(data) {
			b.Fatalf("Failed generating random data %v %d", err, n)
		}
		set.Add(data[:])
		sets[i] = set
	}
	set.Reset()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.Combine(sets[i])
	}
	if set == NewMultiset() { // To prevent optimizing out the loop
		panic("bad benchmark")
	}
}
