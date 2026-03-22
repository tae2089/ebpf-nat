//go:build linux
// +build linux

package nat

import (
	"runtime"
	"testing"

	"github.com/vishvananda/netns"
)

func TestNamespaceCreation(t *testing.T) {
	// Must run on a single thread to maintain namespace context
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	originalNS, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer originalNS.Close()

	env := &TestEnv{
		InternalNSName: "ns-int-test",
		ExternalNSName: "ns-ext-test",
	}

	if err := env.Setup(); err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	defer env.Cleanup()

	// Verify we can enter internal namespace
	err = env.runInNS(env.internalNS, func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Failed to enter internal namespace: %v", err)
	}

	// Verify we can enter external namespace
	err = env.runInNS(env.externalNS, func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Failed to enter external namespace: %v", err)
	}
}
