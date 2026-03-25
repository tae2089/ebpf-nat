package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBearerTokenMiddleware: 메트릭 엔드포인트 Bearer Token 인증 검증
// 토큰이 설정된 경우 올바른 토큰만 통과시키고 잘못된 토큰은 401을 반환해야 한다.
func TestBearerTokenMiddleware(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("metrics data"))
	})

	tests := []struct {
		name           string
		configuredToken string
		requestHeader  string
		expectedStatus int
	}{
		{
			name:           "토큰 미설정 시 모든 요청 통과",
			configuredToken: "",
			requestHeader:  "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "토큰 미설정 시 잘못된 헤더도 통과",
			configuredToken: "",
			requestHeader:  "Bearer wrongtoken",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "올바른 Bearer Token으로 통과",
			configuredToken: "secrettoken123",
			requestHeader:  "Bearer secrettoken123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "잘못된 Bearer Token은 401",
			configuredToken: "secrettoken123",
			requestHeader:  "Bearer wrongtoken",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Authorization 헤더 없으면 401",
			configuredToken: "secrettoken123",
			requestHeader:  "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Bearer 접두사 없으면 401",
			configuredToken: "secrettoken123",
			requestHeader:  "secrettoken123",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Basic 인증 스킴은 401",
			configuredToken: "secrettoken123",
			requestHeader:  "Basic c2VjcmV0dG9rZW4xMjM=",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := BearerTokenMiddleware(tt.configuredToken, innerHandler)

			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if tt.requestHeader != "" {
				req.Header.Set("Authorization", tt.requestHeader)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}
