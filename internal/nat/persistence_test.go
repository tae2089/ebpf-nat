package nat

import (
	"testing"
	"time"
)

func TestTimeConversion(t *testing.T) {
	bootTime := getBootTimeUnixNano()
	if bootTime <= 0 {
		t.Errorf("expected boot time > 0, got %d", bootTime)
	}

	// Wait a bit to ensure time moves forward
	time.Sleep(10 * time.Millisecond)
	
	now := time.Now().UnixNano()
	ktime := unixToKtime(now, bootTime)
	
	// ktime should be approximately now - bootTime
	// Since getBootTimeUnixNano and time.Now() are called at different times, 
	// there might be a small drift, but it should be very small.
	
	convertedUnix := ktimeToUnix(ktime, bootTime)
	if convertedUnix != now {
		t.Errorf("expected %d, got %d", now, convertedUnix)
	}
}

func TestKtimeToUnix(t *testing.T) {
	bootTime := int64(1000000000) // 1 second after epoch
	ktime := uint64(500000000)   // 0.5 seconds after boot
	expected := int64(1500000000) // 1.5 seconds after epoch

	result := ktimeToUnix(ktime, bootTime)
	if result != expected {
		t.Errorf("expected %d, got %d", expected, result)
	}
}

func TestUnixToKtime(t *testing.T) {
	bootTime := int64(1000000000) // 1 second after epoch
	unixNano := int64(1500000000) // 1.5 seconds after epoch
	expected := uint64(500000000) // 0.5 seconds after boot

	result := unixToKtime(unixNano, bootTime)
	if result != expected {
		t.Errorf("expected %d, got %d", expected, result)
	}

	// Test negative case
	unixNano = int64(500000000) // 0.5 seconds after epoch (before boot)
	result = unixToKtime(unixNano, bootTime)
	if result != 0 {
		t.Errorf("expected 0 for time before boot, got %d", result)
	}
}
