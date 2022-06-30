package verifcid

import (
	"testing"

	mh "github.com/multiformats/go-multihash"

	cid "github.com/ipfs/go-cid"
)

func TestValidateCids(t *testing.T) {
	assertTrue := func(v bool) {
		t.Helper()
		if !v {
			t.Fatal("expected success")
		}
	}
	assertFalse := func(v bool) {
		t.Helper()
		if v {
			t.Fatal("expected failure")
		}
	}

	assertTrue(IsGoodHash(mh.SHA2_256))
	assertTrue(IsGoodHash(mh.BLAKE2B_MIN + 32))
	assertTrue(IsGoodHash(mh.DBL_SHA2_256))
	assertTrue(IsGoodHash(mh.KECCAK_256))
	assertTrue(IsGoodHash(mh.SHA3))

	assertTrue(IsGoodHash(mh.SHA1))

	assertFalse(IsGoodHash(mh.BLAKE2B_MIN + 5))

	mhcid := func(code uint64, length int) cid.Cid {
		mhash, err := mh.Sum([]byte{}, code, length)
		if err != nil {
			t.Fatalf("%v: code: %x length: %d", err, code, length)
		}
		return cid.NewCidV1(cid.DagCBOR, mhash)
	}

	cases := []struct {
		cid cid.Cid
		err error
	}{
		{mhcid(mh.SHA2_256, 32), nil},
		{mhcid(mh.SHA2_256, 16), ErrBelowMinimumHashLength},
		{mhcid(mh.MURMUR3X64_64, 4), ErrPossiblyInsecureHashFunction},
		{mhcid(mh.BLAKE3, 32), nil},
	}

	for i, cas := range cases {
		if ValidateCid(cas.cid) != cas.err {
			t.Errorf("wrong result in case of %s (index %d). Expected: %s, got %s",
				cas.cid, i, cas.err, ValidateCid(cas.cid))
		}
	}

}
