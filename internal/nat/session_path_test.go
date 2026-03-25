// session_path_test.go: 세션 파일 경로 검증 단위 테스트 (플랫폼 독립)
package nat

import (
	"testing"

	"github.com/tae2089/ebpf-nat/internal/bpf"
)

// TestValidateSessionPath: 항목 4 - validateSessionPath 단위 테스트
// '..'이 포함되거나 절대 경로가 아닌 경로는 거부해야 한다.
func TestValidateSessionPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "절대 경로 허용",
			path:    "/tmp/sessions.gob",
			wantErr: false,
		},
		{
			name:    "/var/lib 절대 경로 허용",
			path:    "/var/lib/ebpf-nat/sessions.gob",
			wantErr: false,
		},
		{
			name:    "경로 순회 '..' 포함 거부 (/tmp/../etc/passwd)",
			path:    "/tmp/../etc/passwd",
			wantErr: true,
		},
		{
			name:    "경로 순회 '..' 포함 거부 (/var/lib/../../etc/shadow)",
			path:    "/var/lib/../../etc/shadow",
			wantErr: true,
		},
		{
			name:    "상대 경로 거부 (sessions.gob)",
			path:    "sessions.gob",
			wantErr: true,
		},
		{
			name:    "상대 경로 거부 (./sessions.gob)",
			path:    "./sessions.gob",
			wantErr: true,
		},
		{
			name:    "'..' 로 시작하는 경로 거부",
			path:    "../sessions.gob",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSessionPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSessionPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// TestSaveSessions_RejectsPathTraversal: 항목 4
// SaveSessions에 '..'이 포함된 경로를 전달하면 에러를 반환해야 한다.
func TestSaveSessions_RejectsPathTraversal(t *testing.T) {
	objs := &bpf.NatObjects{}
	mgr := NewManager(objs)

	err := mgr.SaveSessions("/tmp/../etc/passwd")
	if err == nil {
		t.Error("expected error for path with '..', got nil")
	}
}

// TestRestoreSessions_RejectsPathTraversal: 항목 4
// RestoreSessions에 '..'이 포함된 경로를 전달하면 에러를 반환해야 한다.
func TestRestoreSessions_RejectsPathTraversal(t *testing.T) {
	objs := &bpf.NatObjects{}
	mgr := NewManager(objs)

	err := mgr.RestoreSessions("/tmp/../etc/shadow")
	if err == nil {
		t.Error("expected error for path with '..', got nil")
	}
}
