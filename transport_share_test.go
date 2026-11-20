//go:build sharetransport

package kolosync

import (
	"strconv"
	"strings"
	"testing"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// transportNamed returns the transport of the share app for name "share[,stream MiB,conn MiB[,congestion]]": window growth
// from kolo-transport's default window to 4 MiB a stream and 8 MiB a connection (or the sizes given), and BBR (or
// the controller given). The versions of kolo-secure and kolo-transport that have window growth are newer than go.mod's, so
// it is built only with the tag, in a workspace that has them.
func transportNamed(t *testing.T, name string) func() (*kolosecure.Config, func(*kolosecure.Conn)) {
	t.Helper()
	f := strings.Split(name, ",")
	if f[0] != "share" {
		t.Fatalf("transport %q: want share[,stream MiB,conn MiB[,congestion]]", name)
	}
	stream, conn, cc := int64(4), int64(8), "bbr"
	if len(f) >= 3 {
		var err error
		if stream, err = strconv.ParseInt(f[1], 10, 64); err != nil {
			t.Fatal(err)
		}
		if conn, err = strconv.ParseInt(f[2], 10, 64); err != nil {
			t.Fatal(err)
		}
	}
	if len(f) == 4 {
		cc = f[3]
	}
	return func() (*kolosecure.Config, func(*kolosecure.Conn)) {
		tc := &kolotransport.Config{
			WindowGrowth:                true,
			MaxStreamReceiveWindow:      kolotransport.DefaultMaxStreamReceiveWindow,
			MaxConnReceiveWindow:        kolotransport.DefaultMaxStreamReceiveWindow,
			MaxGrownStreamReceiveWindow: stream << 20,
			MaxGrownConnReceiveWindow:   conn << 20,
			MaxGrownMemory:              16 * (conn<<20 - kolotransport.DefaultMaxStreamReceiveWindow),
			CongestionControl:           cc,
		}
		return &kolosecure.Config{Transport: tc}, func(c *kolosecure.Conn) { c.AllowWindowGrowth() }
	}
}

// tunedPebble opens Pebble as the share app does: a 256 MiB memtable and no compression, which suit ciphertext.
func tunedPebble(dir string) (kolostore.Backend, error) {
	return kolostore.OpenPebbleWith(dir, kolostore.PebbleOptions{MemTableSize: 256 << 20, NoCompression: true})
}
