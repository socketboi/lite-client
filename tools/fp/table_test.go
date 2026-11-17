package main

import (
	"reflect"
	"testing"
)

func TestSignatureGREASEDoesNotFreezeCapturedDraw(t *testing.T) {
	// Chrome 155 draws a separate signature-algorithm GREASE value
	// (vendor/utls/u_parrots.go:3212-3217). Only that draw may be normalised.
	first := Extension{Type: extSignatureAlgorithms, Data: []byte{0, 6, 0x3a, 0x3a, 9, 4, 4, 3}}
	second := Extension{Type: extSignatureAlgorithms, Data: []byte{0, 6, 0xea, 0xea, 9, 4, 4, 3}}
	a, err := tableExt(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tableExt(second)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a.GreaseAt, []int{2}) {
		t.Fatalf("per-connection GREASE draw became fingerprint data: %#v / %#v", a, b)
	}
	second.Data[5] = 5
	b, err = tableExt(second)
	if err != nil || reflect.DeepEqual(a, b) {
		t.Fatal("a changed real signature scheme must remain observable")
	}
	second.Data = []byte{0, 6, 9, 4, 0xea, 0xea, 4, 3}
	b, err = tableExt(second)
	if err != nil || reflect.DeepEqual(a, b) {
		t.Fatal("moving GREASE within the signature list must remain observable")
	}
}
