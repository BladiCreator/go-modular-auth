package sdk_test

import (
	"strconv"
	"sync"
	"testing"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// TestSDKContext_ConcurrentSetGet must be run with -race: concurrent access
// to the context bag used to be an unsynchronized map write.
func TestSDKContext_ConcurrentSetGet(t *testing.T) {
	c := sdk.NewContext(nil)
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			c.Set("k"+strconv.Itoa(i%8), i)
		}()
		go func() {
			defer wg.Done()
			_, _ = c.Get("k" + strconv.Itoa(i%8))
		}()
	}
	wg.Wait()
	if _, ok := c.Get("k0"); !ok {
		t.Fatal("expected key k0 to be set")
	}
}
