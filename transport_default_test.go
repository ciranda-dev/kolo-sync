//go:build !sharetransport

package kolosync

import (
	"errors"
	"testing"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
)

// tunedPebble needs the kolo-store that has OpenPebbleWith, which is newer than go.mod's: build with -tags sharetransport.
func tunedPebble(string) (kolostore.Backend, error) {
	return nil, errors.New("pebble-tuned needs -tags sharetransport")
}

// transportNamed has only the default transport; the share app's needs the sharetransport build tag.
func transportNamed(t *testing.T, name string) func() (*kolosecure.Config, func(*kolosecure.Conn)) {
	t.Helper()
	t.Skipf("transport %q needs -tags sharetransport", name)
	return nil
}
