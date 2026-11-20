package kolosync

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func samples() []message {
	key := bytes.Repeat([]byte{7}, keySize)
	signed := func(c byte) []byte { return bytes.Repeat([]byte{c}, minSigned) }
	return []message{
		{typ: tHeadReq, owner: [keySize]byte{9, 8}, logID: kololog.LogID{1, 2, 3}},
		{typ: tProofReq, a: 3, b: 300},
		{typ: tEntriesReq, a: 0, b: 1 << 40, keys: true},
		{typ: tStateReq, a: 5, b: 9, keys: true},
		{typ: tHead, head: []byte("head"), header: []byte("header")},
		{typ: tProof, proof: []byte("proof")},
		{typ: tEntries, entries: []kololog.Entry{
			{Record: signed('r'), Ciphertext: []byte("c0"), Marker: []byte{}, Key: key},
			{Record: signed('s'), Ciphertext: []byte{}, Marker: signed('m'), Key: []byte{}},
		}},
		{typ: tState, a: 10, items: []item{{index: 2, marker: signed('m')}, {index: 4, key: key}}},
		{typ: tError, code: codeBusy},
		{typ: tFetchReq, a: 2, b: 5, size: 1 << 50},
		{typ: tStreamReq, a: 7, size: 1 << 40, keys: true, credit: 2 << 20},
		{typ: tStreamReq, a: 0, size: 1, credit: 1},
		{typ: tCreditReq, credit: 64 << 20},
		{typ: tFetch, entries: []kololog.Entry{
			{Record: signed('r'), Ciphertext: []byte("c0"), Marker: []byte{}, Key: key},
			{Record: signed('s'), Ciphertext: []byte{}, Marker: signed('m'), Key: []byte{}},
		}, proofs: [][]byte{[]byte("p0"), []byte("p1")}},
	}
}

func TestRoundTrip(t *testing.T) {
	for _, m := range samples() {
		got, err := decode(encode(m), request(m.typ))
		if err != nil {
			t.Fatalf("type %d: %v", m.typ, err)
		}
		if f := frameOf(m); cap(f) != 4+bound(m) {
			t.Fatalf("type %d: the frame grew past its presized slice", m.typ)
		}
		if !bytes.Equal(encode(got), encode(m)) {
			t.Fatalf("type %d: re-encodes differently", m.typ)
		}
		if m.typ != tEntries && m.typ != tState && m.typ != tFetch && !reflect.DeepEqual(got, m) {
			t.Fatalf("type %d: decoded %+v, want %+v", m.typ, got, m)
		}
	}
}

func TestFormat(t *testing.T) {
	got := wire(message{typ: tProofReq, a: 3, b: 300})
	want := []byte{5, 0, 0, 0, version, tProofReq, 3, 0xac, 0x02}
	if !bytes.Equal(got, want) {
		t.Fatalf("PROOF_REQ = %x, want %x", got, want)
	}
}

func TestFormatStream(t *testing.T) {
	got := wire(message{typ: tStreamReq, a: 3, size: 300, keys: true, credit: 2 << 20})
	want := []byte{10, 0, 0, 0, version, tStreamReq, 3, 0xac, 0x02, 1, 0x80, 0x80, 0x80, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("STREAM_REQ = %x, want %x", got, want)
	}
	got = wire(message{typ: tCreditReq, credit: 5})
	want = []byte{3, 0, 0, 0, version, tCreditReq, 5}
	if !bytes.Equal(got, want) {
		t.Fatalf("CREDIT_REQ = %x, want %x", got, want)
	}
	// Only a server takes them.
	for _, typ := range []uint64{tStreamReq, tCreditReq} {
		if !request(typ) {
			t.Errorf("type %d is not a request", typ)
		}
	}
}

func TestDecodeRejects(t *testing.T) {
	key := bytes.Repeat([]byte{7}, keySize)
	// A FETCH with one entry whose proof is missing.
	fetchEntry := append(putBytes([]byte{version, tFetch, 1}, make([]byte, minSigned)), 0, 0, 0)
	fetchEntry = fetchEntry[:len(fetchEntry):len(fetchEntry)]
	if _, err := decode(putBytes(fetchEntry, []byte{1}), false); err != nil {
		t.Fatalf("FETCH with a proof: %v", err)
	}
	for name, b := range map[string][]byte{
		"empty":              nil,
		"version 0":          {0, tError, codeBusy},
		"unknown type":       {version, tCreditReq + 1},
		"type 0":             {version, 0},
		"error code 0":       {version, tError, 0},
		"error code 5":       {version, tError, 5},
		"trailing byte":      {version, tError, codeBusy, 0},
		"non-minimal varint": {version, 0x89, 0x00, codeBusy},
		"short log ID":       append([]byte{version, tHeadReq}, make([]byte, keySize+31)...),
		"entry count":        {version, tEntries, 2, 0, 0, 0, 0},
		"short key":          {version, tEntries, 1, 0, 0, 0, 1, 9},
		"item count":         {version, tState, 0, 2, 0, 0, 0},
		"item kind 2":        {version, tState, 9, 1, 0, 2, 0},
		"items out of order": append(append([]byte{version, tState, 9, 2, 3, 1, keySize}, key...), append([]byte{3, 1, keySize}, key...)...),
		"item short key":     {version, tState, 9, 1, 0, 1, 1, 9},
		"oversized head":     append([]byte{version, tHead, 0x81, 0x40}, make([]byte, maxSmall+1)...),
		"a request":          append([]byte{version, tHeadReq}, make([]byte, keySize+32)...),
		"short record":       append([]byte{version, tEntries, 1, minSigned - 1}, make([]byte, minSigned-1+3)...),
		"short marker":       append([]byte{version, tState, 9, 1, 0, 0, minSigned - 1}, make([]byte, minSigned-1)...),
		"fetch no proof":     fetchEntry,
		"fetch long proof":   putBytes(fetchEntry, make([]byte, maxSmall+1)),
	} {
		if _, err := decode(b, false); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want ErrProtocol", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"FETCH_REQ no size":  {version, tFetchReq, 1, 2},
		"FETCH_REQ trailing": {version, tFetchReq, 1, 2, 3, 0},
	} {
		if _, err := decode(b, true); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want ErrProtocol", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"STREAM_REQ no credit":       {version, tStreamReq, 1, 2, 1},
		"STREAM_REQ no keys":         {version, tStreamReq, 1, 2},
		"STREAM_REQ keys 2":          {version, tStreamReq, 1, 2, 2, 5},
		"STREAM_REQ trailing":        {version, tStreamReq, 1, 2, 1, 5, 0},
		"STREAM_REQ long credit":     {version, tStreamReq, 1, 2, 1, 0x85, 0x00},
		"STREAM_REQ credit too long": append([]byte{version, tStreamReq, 1, 2, 1}, bytes.Repeat([]byte{0xff}, 11)...),
		"CREDIT_REQ empty":           {version, tCreditReq},
		"CREDIT_REQ trailing":        {version, tCreditReq, 5, 0},
		"CREDIT_REQ non-minimal":     {version, tCreditReq, 0x85, 0x00},
	} {
		if _, err := decode(b, true); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want ErrProtocol", name, err)
		}
	}
	for name, b := range map[string][]byte{
		"STATE_REQ keys 2":   {version, tStateReq, 1, 2, 2},
		"ENTRIES_REQ keys 2": {version, tEntriesReq, 1, 2, 2},
	} {
		if _, err := decode(b[:len(b)-1], true); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s without its bool: %v, want ErrProtocol", name, err)
		}
		if _, err := decode(append(b[:len(b)-1:len(b)-1], 1), true); err != nil {
			t.Errorf("%s with keys 1: %v", name, err)
		}
		if _, err := decode(b, true); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want ErrProtocol", name, err)
		}
	}
}

func TestDecodeDirection(t *testing.T) {
	for _, m := range samples() {
		if _, err := decode(encode(m), !request(m.typ)); !errors.Is(err, ErrProtocol) {
			t.Errorf("type %d decoded in the wrong direction: %v", m.typ, err)
		}
	}
}

func TestReadFrame(t *testing.T) {
	ok := wire(message{typ: tError, code: codeNotFound})
	if m, err := readFrame(bytes.NewReader(ok), false, nil); err != nil || m.code != codeNotFound {
		t.Fatalf("readFrame = %+v, %v", m, err)
	}
	for name, tc := range map[string]struct {
		b    []byte
		want error
	}{
		"empty":         {nil, ErrProtocol},
		"zero length":   {frame(0, nil), ErrProtocol},
		"over max":      {frame(MaxMessageSize+1, nil), ErrTooLarge},
		"short payload": {ok[:len(ok)-1], ErrProtocol},
	} {
		if _, err := readFrame(bytes.NewReader(tc.b), false, nil); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

func TestLargestMessages(t *testing.T) {
	ct := make([]byte, MaxMessageSize-overhead-entrySize(kololog.Entry{Record: make([]byte, 300)}))
	m := message{typ: tEntries, entries: []kololog.Entry{{Record: make([]byte, 300), Ciphertext: ct}}}
	if n := len(encode(m)); n > MaxMessageSize {
		t.Fatalf("an entry within the budget encodes to %d bytes", n)
	}
}

func TestDecodeHugeCount(t *testing.T) {
	huge := binary.AppendUvarint(nil, 1<<60)
	for name, b := range map[string][]byte{
		"entries": append([]byte{version, tEntries}, huge...),
		"fetch":   append([]byte{version, tFetch}, huge...),
		"items":   append([]byte{version, tState, 0}, huge...),
	} {
		if _, err := decode(b, false); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want ErrProtocol", name, err)
		}
	}
}

func TestReadFrameHooks(t *testing.T) {
	m := message{typ: tEntries, entries: []kololog.Entry{{Record: make([]byte, minSigned), Ciphertext: make([]byte, 100)}}}
	b := wire(m)
	var size int
	var first []byte
	got, err := readFrameWith(bytes.NewReader(b), false, frameHooks{
		size: func(n int) error { size = n; return nil },
		peek: func(n int, p []byte) error {
			if n != size {
				t.Errorf("peek told a body of %d bytes, size said %d", n, size)
			}
			first = append(first, p...)
			return nil
		},
	})
	if err != nil || len(got.entries) != 1 {
		t.Fatalf("readFrameWith = %+v, %v", got, err)
	}
	if size != len(b)-4 || !bytes.Equal(first, b[4:4+min(size, peekSize)]) {
		t.Fatalf("hooks saw a body of %d bytes starting %x", size, first)
	}
	// A hook that refuses ends the read with its error, and a refused size reads nothing more.
	refuse := errors.New("refused")
	for name, h := range map[string]frameHooks{
		"size": {size: func(int) error { return refuse }},
		"peek": {peek: func(int, []byte) error { return refuse }},
	} {
		r := bytes.NewReader(b)
		if _, err := readFrameWith(r, false, h); err != refuse {
			t.Errorf("%s hook: %v, want its error", name, err)
		}
		if name == "size" && r.Len() != len(b)-4 {
			t.Errorf("a refused size left %d bytes unread, want %d", r.Len(), len(b)-4)
		}
	}
	// A body shorter than the peek is read whole.
	short := wire(message{typ: tError, code: codeBusy})
	var seen int
	if _, err := readFrameWith(bytes.NewReader(short), false, frameHooks{peek: func(_ int, p []byte) error { seen = len(p); return nil }}); err != nil || seen != len(short)-4 {
		t.Fatalf("short body: peek saw %d of %d bytes, %v", seen, len(short)-4, err)
	}
}

// The wait for memory in the size hook is not the peer's time: the body of an answer may arrive in full after the hook
// has held the reader for longer than the timeout.
func TestReadAnswerDeadlineStartsAfterTheSizeHook(t *testing.T) {
	was := timeout
	timeout = 300 * time.Millisecond
	t.Cleanup(func() { timeout = was })
	checkGoroutines(t)
	a, b := newPeer(t), newPeer(t)
	a.srv = nil
	ba, ab := connect(t, b, a, nil)
	acceptServe(t, ab, func(st *kolotransport.Stream) {
		readMsg(st, true)
		writeMsg(st, message{typ: tProof, proof: []byte{1, 2, 3}})
	})
	st := rawStream(t, ba)
	if _, err := writeMsg(st, headReq(a.id.PublicKey(), kololog.LogID{1})); err != nil {
		t.Fatal(err)
	}
	m, err := readAnswer(st, frameHooks{size: func(int) error {
		time.Sleep(2 * timeout)
		return nil
	}})
	if err != nil || m.typ != tProof {
		t.Fatalf("readAnswer = %+v, %v", m, err)
	}
}
