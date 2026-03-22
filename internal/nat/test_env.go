package nat

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type TestEnv struct {
	InternalNSName string
	ExternalNSName string

	internalNS netns.NsHandle
	externalNS netns.NsHandle
	rootNS     netns.NsHandle
}

func (e *TestEnv) Setup() error {
	var err error
	e.rootNS, err = netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root ns: %w", err)
	}

	// 1. Create Namespaces
	// Note: vishvananda/netns doesn't have a direct 'NewWithName' that also mounts it in /var/run/netns.
	// We'll create them and we can refer to them by handle. 
	// To make them "Named" (visible to `ip netns`), we'd need to bind mount them.
	// For simplicity in this test runner, we'll just use the handles.
	
	e.internalNS, err = netns.New()
	if err != nil {
		return fmt.Errorf("failed to create internal ns: %w", err)
	}
	// Switch back to root to create the next one
	netns.Set(e.rootNS)

	e.externalNS, err = netns.New()
	if err != nil {
		return fmt.Errorf("failed to create external ns: %w", err)
	}
	netns.Set(e.rootNS)

	// 2. Setup Connectivity (veth pairs)
	if err := e.setupVeth("veth-int-root", "veth-int", e.internalNS, "192.168.1.1/24", "192.168.1.10/24"); err != nil {
		return err
	}

	if err := e.setupVeth("veth-ext-root", "veth-ext", e.externalNS, "10.0.0.1/24", "10.0.0.10/24"); err != nil {
		return err
	}

	// 3. Enable IP Forwarding in Root NS
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %w", err)
	}

	// 4. Setup Routing in Internal NS (Default GW)
	err = e.runInNS(e.internalNS, func() error {
		link, err := netlink.LinkByName("veth-int")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{
			Scope:     netlink.SCOPE_UNIVERSE,
			LinkIndex: link.Attrs().Index,
			Gw:        net.ParseIP("192.168.1.1"),
		})
	})
	if err != nil {
		return fmt.Errorf("failed to setup routing in internal ns: %w", err)
	}

	// 5. Setup Routing in External NS
	err = e.runInNS(e.externalNS, func() error {
		link, err := netlink.LinkByName("veth-ext")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	})
	if err != nil {
		return err
	}

	return netns.Set(e.rootNS)
}

func (e *TestEnv) setupVeth(rootName, peerName string, peerNS netns.NsHandle, rootIP, peerIP string) error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: rootName},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to add veth pair %s: %w", rootName, err)
	}

	// Assign IP to root end
	rootLink, err := netlink.LinkByName(rootName)
	if err != nil {
		return err
	}
	addr, _ := netlink.ParseAddr(rootIP)
	if err := netlink.AddrAdd(rootLink, addr); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(rootLink); err != nil {
		return err
	}

	// Move peer end to namespace
	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetNsFd(peerLink, int(peerNS)); err != nil {
		return err
	}

	// Assign IP to peer end in its namespace
	return e.runInNS(peerNS, func() error {
		link, err := netlink.LinkByName(peerName)
		if err != nil {
			return err
		}
		addr, _ := netlink.ParseAddr(peerIP)
		if err := netlink.AddrAdd(link, addr); err != nil {
			return err
		}
		return netlink.LinkSetUp(link)
	})
}

func (e *TestEnv) runInNS(ns netns.NsHandle, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNS, _ := netns.Get()
	defer currentNS.Close()

	if err := netns.Set(ns); err != nil {
		return err
	}
	defer netns.Set(currentNS)

	return f()
}

func (e *TestEnv) Cleanup() {
	if e.internalNS > 0 {
		e.internalNS.Close()
	}
	if e.externalNS > 0 {
		e.externalNS.Close()
	}
	if e.rootNS > 0 {
		e.rootNS.Close()
	}
}
