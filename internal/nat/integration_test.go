//go:build linux
// +build linux

package nat

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/tae2089/ebpf-nat/internal/bpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func runCmd(cmd string) (string, error) {
	c := exec.Command("bash", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("cmd failed: %s, output: %s", err, string(out))
	}
	return string(out), nil
}

func TestNamespaceCreation(t *testing.T) {
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

	if err := env.Setup(nil); err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	defer env.Cleanup()

	err = env.runInNS(env.internalNS, func() error {
		_, err := runCmd("ping -c 1 -W 1 10.0.0.10")
		return err
	})
	if err != nil {
		t.Errorf("Failed to ping external from internal (no NAT): %v", err)
	}
}

func TestNATConnectivity(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bpf.StartTracePipeLogger(ctx)

	objs := bpf.NatObjects{}
	if err := bpf.LoadNatObjects(&objs, nil); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	// Configure NAT gateway external IP (matching veth-ext-root)
	externalIP := net.ParseIP("10.0.0.1")
	if err := objs.SnatConfigMap.Update(uint32(0), bpf.NatSnatConfig{
		ExternalIp: ipToUint32(externalIP),
	}, 0); err != nil {
		t.Fatal(err)
	}

	env := &TestEnv{
		InternalNSName: "ns-int-conn",
		ExternalNSName: "ns-ext-conn",
	}
	if err := env.Setup(&objs); err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	defer env.Cleanup()

	// 0. Diagnostic: Log IP and Route info
	t.Run("Diagnostics", func(t *testing.T) {
		out, _ := runCmd("ip addr")
		t.Logf("Root NS interfaces:\n%s", out)

		env.runInNS(env.internalNS, func() error {
			out, _ := runCmd("ip addr")
			t.Logf("Internal NS addr:\n%s", out)
			out, _ = runCmd("ip route")
			t.Logf("Internal NS route:\n%s", out)
			return nil
		})

		env.runInNS(env.externalNS, func() error {
			out, _ := runCmd("ip addr")
			t.Logf("External NS addr:\n%s", out)
			out, _ = runCmd("ip route")
			t.Logf("External NS route:\n%s", out)
			out, _ = runCmd("ip neigh")
			t.Logf("External NS neigh:\n%s", out)
			return nil
		})
	})

	// 0.1 Diagnostic: Ping gateway from Internal NS
	t.Run("PingGateway", func(t *testing.T) {
		err := env.runInNS(env.internalNS, func() error {
			_, err := runCmd("ping -c 1 -W 1 192.168.1.1")
			return err
		})
		if err != nil {
			t.Errorf("Failed to ping gateway from internal: %v", err)
		}
	})

	// 0.2 Diagnostic: Ping external IP from Internal NS
	t.Run("PingExternal", func(t *testing.T) {
		err := env.runInNS(env.internalNS, func() error {
			_, err := runCmd("ping -c 1 -W 1 10.0.0.10")
			return err
		})
		if err != nil {
			t.Errorf("Failed to ping external from internal: %v", err)
		}
	})

	// 0.3 Diagnostic: Ping gateway from External NS
	t.Run("PingGatewayFromExternal", func(t *testing.T) {
		err := env.runInNS(env.externalNS, func() error {
			_, err := runCmd("ping -c 1 -W 1 10.0.0.1")
			return err
		})
		if err != nil {
			t.Errorf("Failed to ping gateway from external: %v", err)
		}
	})

	// 1. TCP Connectivity Test
	t.Run("TCP", func(t *testing.T) {
		serverAddr := "10.0.0.10:8080"
		receivedChan := make(chan string, 1)

		// Start server in External NS
		go func() {
			err := env.runInNS(env.externalNS, func() error {
				l, err := net.Listen("tcp", serverAddr)
				if err != nil {
					return err
				}
				defer l.Close()

				// Set timeout for accept
				l.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))

				conn, err := l.Accept()
				if err != nil {
					return err
				}
				defer conn.Close()

				remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
				if !remoteAddr.IP.Equal(externalIP) {
					receivedChan <- fmt.Sprintf("wrong src ip: %v", remoteAddr.IP)
					return nil
				}

				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				receivedChan <- string(buf[:n])
				return nil
			})
			if err != nil {
				receivedChan <- fmt.Sprintf("server error: %v", err)
			}
		}()

		time.Sleep(500 * time.Millisecond)

		// Connect from Internal NS
		err := env.runInNS(env.internalNS, func() error {
			conn, err := net.DialTimeout("tcp", serverAddr, 2*time.Second)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte("hello tcp"))
			return err
		})
		if err != nil {
			t.Logf("TCP client failed: %v", err)
		}

		select {
		case msg := <-receivedChan:
			if msg != "hello tcp" {
				t.Errorf("TCP server received wrong message: %s", msg)
			}
		case <-time.After(3 * time.Second):
			t.Error("TCP server timeout")
		}
	})

	// 2. UDP Connectivity Test
	t.Run("UDP", func(t *testing.T) {
		serverAddr := "10.0.0.10:9090"
		receivedChan := make(chan string, 1)

		// Start server in External NS
		go func() {
			err := env.runInNS(env.externalNS, func() error {
				addr, err := net.ResolveUDPAddr("udp", serverAddr)
				if err != nil {
					return err
				}
				conn, err := net.ListenUDP("udp", addr)
				if err != nil {
					return err
				}
				defer conn.Close()

				conn.SetDeadline(time.Now().Add(5 * time.Second))

				buf := make([]byte, 1024)
				n, remoteAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					return err
				}

				if !remoteAddr.IP.Equal(externalIP) {
					receivedChan <- fmt.Sprintf("wrong src ip: %v", remoteAddr.IP)
					return nil
				}

				receivedChan <- string(buf[:n])
				return nil
			})
			if err != nil {
				receivedChan <- fmt.Sprintf("server error: %v", err)
			}
		}()

		time.Sleep(500 * time.Millisecond)

		// Send from Internal NS
		err := env.runInNS(env.internalNS, func() error {
			addr, err := net.ResolveUDPAddr("udp", serverAddr)
			if err != nil {
				return err
			}
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				return err
			}
			defer conn.Close()
			_, err = conn.Write([]byte("hello udp"))
			return err
		})
		if err != nil {
			t.Logf("UDP client failed: %v", err)
		}

		select {
		case msg := <-receivedChan:
			if msg != "hello udp" {
				t.Errorf("UDP server received wrong message: %s", msg)
			}
		case <-time.After(3 * time.Second):
			t.Error("UDP server timeout")
		}
	})

	// 3. PMTU Discovery Test
	t.Run("PMTU", func(t *testing.T) {
		// Set smaller MTU on gateway external interface
		link, err := netlink.LinkByName("veth-ext-root")
		if err != nil {
			t.Fatalf("Failed to find veth-ext-root: %v", err)
		}
		if err := netlink.LinkSetMTU(link, 1400); err != nil {
			t.Fatalf("Failed to set MTU: %v", err)
		}

		// Reset MTU after test
		defer netlink.LinkSetMTU(link, 1500)

		// Send large ping from Internal NS with DF (Don't Fragment) bit
		err = env.runInNS(env.internalNS, func() error {
			// -s 1450 sends a packet larger than 1400 MTU
			// -M do sets DF bit
			out, err := runCmd("ping -c 1 -W 1 -s 1450 -M do 10.0.0.10")
			if err == nil {
				return fmt.Errorf("expected ping to fail due to MTU, output: %s", out)
			}
			t.Logf("Ping failed as expected: %v, output: %s", err, out)
			return nil
		})
		if err != nil {
			t.Errorf("PMTU discovery failed: %v", err)
		}
	})

	// 4. Metrics Verification Test
	t.Run("Metrics", func(t *testing.T) {
		// Wait a bit for all packets to be processed and metrics updated
		time.Sleep(500 * time.Millisecond)

		var foundTCP, foundUDP bool
		var key bpf.NatMetricsKey
		var values []bpf.NatMetricsValue
		iter := objs.MetricsMap.Iterate()

		for iter.Next(&key, &values) {
			var totalPackets uint64
			for _, v := range values {
				totalPackets += v.Packets
			}

			if totalPackets > 0 {
				if key.Protocol == syscall.IPPROTO_TCP && key.Action == 0 { // Translated
					foundTCP = true
					t.Logf("Found TCP metrics: %d packets", totalPackets)
				}
				if key.Protocol == syscall.IPPROTO_UDP && key.Action == 0 { // Translated
					foundUDP = true
					t.Logf("Found UDP metrics: %d packets", totalPackets)
				}
			}
		}

		if err := iter.Err(); err != nil {
			t.Errorf("Failed to iterate metrics map: %v", err)
		}

		if !foundTCP {
			t.Error("TCP metrics not found or zero packets")
		}
		if !foundUDP {
			t.Error("UDP metrics not found or zero packets")
		}
	})

	// 5. Session Persistence Test
	t.Run("Persistence", func(t *testing.T) {
		mgr := NewManager(&objs)
		mgr.udpTimeout = 5 * time.Minute
		mgr.tcpTimeout = 24 * time.Hour
		sessionFile := "/tmp/ebpf-nat-sessions.gob"

		// Ensure there are some sessions from previous tests (UDP/TCP)
		var count int
		iter := objs.ConntrackMap.Iterate()
		var k bpf.NatNatKey
		var v bpf.NatNatEntry
		for iter.Next(&k, &v) {
			count++
		}
		if count == 0 {
			t.Fatal("No sessions found in ConntrackMap to persist")
		}
		t.Logf("Found %d sessions to persist", count)

		// Save sessions
		if err := mgr.SaveSessions(sessionFile); err != nil {
			t.Fatalf("Failed to save sessions: %v", err)
		}

		// Clear maps
		if _, err := objs.ConntrackMap.BatchDelete(nil, nil); err != nil {
			// Fallback to manual delete if BatchDelete(nil, nil) is not supported
			iter = objs.ConntrackMap.Iterate()
			for iter.Next(&k, &v) {
				objs.ConntrackMap.Delete(k)
			}
		}
		if _, err := objs.ReverseNatMap.BatchDelete(nil, nil); err != nil {
			iter = objs.ReverseNatMap.Iterate()
			for iter.Next(&k, &v) {
				objs.ReverseNatMap.Delete(k)
			}
		}

		// Verify maps are empty
		count = 0
		iter = objs.ConntrackMap.Iterate()
		for iter.Next(&k, &v) {
			count++
		}
		if count != 0 {
			t.Fatalf("ConntrackMap not empty after clear: %d entries", count)
		}

		// Restore sessions
		if err := mgr.RestoreSessions(sessionFile); err != nil {
			t.Fatalf("Failed to restore sessions: %v", err)
		}

		// Verify sessions are back
		count = 0
		iter = objs.ConntrackMap.Iterate()
		for iter.Next(&k, &v) {
			count++
		}
		if count == 0 {
			t.Fatal("No sessions restored in ConntrackMap")
		}
		t.Logf("Successfully restored %d sessions", count)
	})

	// 6. Anti-Spoofing Test
	t.Run("AntiSpoofing", func(t *testing.T) {
		// Enable anti-spoofing for 192.168.1.0/24
		internalNet := "192.168.1.0/24"
		_, ipnet, _ := net.ParseCIDR(internalNet)
		
		// Update BPF config directly
		if err := objs.SnatConfigMap.Update(uint32(0), bpf.NatSnatConfig{
			ExternalIp:   ipToUint32(externalIP),
			InternalNet:  ipToUint32(ipnet.IP),
			InternalMask: binary.LittleEndian.Uint32(ipnet.Mask),
		}, 0); err != nil {
			t.Fatal(err)
		}

		// Try to send a packet with a spoofed IP from internal NS
		err := env.runInNS(env.internalNS, func() error {
			// Add a spoofed IP to the interface
			runCmd("ip addr add 1.2.3.4/24 dev veth-int")
			defer runCmd("ip addr del 1.2.3.4/24 dev veth-int")

			// ping from spoofed IP should fail (dropped by eBPF)
			out, err := runCmd("ping -c 1 -W 1 -I 1.2.3.4 10.0.0.10")
			if err == nil {
				return fmt.Errorf("expected spoofed ping to fail, but it succeeded: %s", out)
			}
			t.Logf("Spoofed ping failed as expected: %v", err)
			return nil
		})
		if err != nil {
			t.Errorf("Anti-spoofing test failed: %v", err)
		}
		
		// Reset config to disable anti-spoofing for other tests if any
		objs.SnatConfigMap.Update(uint32(0), bpf.NatSnatConfig{
			ExternalIp: ipToUint32(externalIP),
		}, 0)
	})

	// Give some time for BPF logs
	time.Sleep(200 * time.Millisecond)
}
