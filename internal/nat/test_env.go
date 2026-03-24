//go:build linux
// +build linux

package nat

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/tae2089/ebpf-nat/internal/bpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type TestEnv struct {
	InternalNSName string
	ExternalNSName string

	internalNS netns.NsHandle
	externalNS netns.NsHandle
	rootNS     netns.NsHandle

	objs *bpf.NatObjects
}

func (e *TestEnv) Setup(objs *bpf.NatObjects) error {
	var err error
	e.objs = objs
	e.rootNS, err = netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root ns: %w", err)
	}

	// 1. Create Namespaces
	e.internalNS, err = netns.New()
	if err != nil {
		return fmt.Errorf("failed to create internal ns: %w", err)
	}
	netns.Set(e.rootNS)

	e.externalNS, err = netns.New()
	if err != nil {
		return fmt.Errorf("failed to create external ns: %w", err)
	}
	netns.Set(e.rootNS)

	// 2. Setup Connectivity
	// Internal IP: 192.168.1.10 -> GW: 192.168.1.1
	if err := e.setupVeth("veth-int-root", "veth-int", e.internalNS, "192.168.1.1/24", "192.168.1.10/24"); err != nil {
		return err
	}

	// External Target: 10.0.0.10 -> GW: 10.0.0.1
	if err := e.setupVeth("veth-ext-root", "veth-ext", e.externalNS, "10.0.0.1/24", "10.0.0.10/24"); err != nil {
		return err
	}

	// 3. Enable IP Forwarding and disable rp_filter
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable ip_forward: %w", err)
	}
	// Allow forwarding in iptables (Docker might have set it to DROP)
	exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()

	if err := os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0"), 0644); err != nil {
		return fmt.Errorf("failed to disable all rp_filter: %w", err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/default/rp_filter", []byte("0"), 0644); err != nil {
		return fmt.Errorf("failed to disable default rp_filter: %w", err)
	}
	// Specifically for veth interfaces
	links := []string{"veth-int-root", "veth-ext-root"}
	for _, l := range links {
		path := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", l)
		if err := os.WriteFile(path, []byte("0"), 0644); err != nil {
			// Ignore error if interface not yet created
		}
		// Disable offloads to ensure BPF sees clean packets and checksums work
		exec.Command("ethtool", "-K", l, "rx", "off", "tx", "off", "tso", "off", "gso", "off", "gro", "off").Run()
	}
	// Enable proxy_arp on external interface
	os.WriteFile("/proc/sys/net/ipv4/conf/veth-ext-root/proxy_arp", []byte("1"), 0644)

	// 4. Attach eBPF NAT only to the EXTERNAL interface
	if e.objs != nil {
		if err := e.attachBPF("veth-ext-root"); err != nil {
			return err
		}
	}

	// 5. Setup Routing in Internal NS
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
		return err
	}

	// 6. Setup Routing in External NS
	return e.runInNS(e.externalNS, func() error {
		link, err := netlink.LinkByName("veth-ext")
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		// Return route to internal network via gateway
		return netlink.RouteAdd(&netlink.Route{
			Dst:       &net.IPNet{IP: net.ParseIP("192.168.1.0"), Mask: net.CIDRMask(24, 32)},
			LinkIndex: link.Attrs().Index,
			Gw:        net.ParseIP("10.0.0.1"),
		})
	})
}

func (e *TestEnv) attachBPF(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	_ = netlink.QdiscAdd(qdisc)

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           e.objs.TcNatIngress.FD(),
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filterIngress); err != nil {
		return fmt.Errorf("ingress filter on %s: %w", ifName, err)
	}

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		Fd:           e.objs.TcNatEgress.FD(),
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filterEgress); err != nil {
		return fmt.Errorf("egress filter on %s: %w", ifName, err)
	}
	return nil
}

func (e *TestEnv) setupVeth(rootName, peerName string, peerNS netns.NsHandle, rootIP, peerIP string) error {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: rootName},
		PeerName:  peerName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}

	rootLink, _ := netlink.LinkByName(rootName)
	addr, _ := netlink.ParseAddr(rootIP)
	if err := netlink.AddrAdd(rootLink, addr); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(rootLink); err != nil {
		return err
	}

	peerLink, _ := netlink.LinkByName(peerName)
	if err := netlink.LinkSetNsFd(peerLink, int(peerNS)); err != nil {
		return err
	}

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
	// Delete interfaces from root
	links := []string{"veth-int-root", "veth-ext-root"}
	for _, l := range links {
		if link, err := netlink.LinkByName(l); err == nil {
			netlink.LinkDel(link)
		}
	}
}
