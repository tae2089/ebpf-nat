package metrics

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// BearerTokenMiddleware는 메트릭 엔드포인트에 Bearer Token 인증을 추가하는 미들웨어다.
// token이 비어있으면 모든 요청을 통과시킨다 (하위 호환).
// token이 설정된 경우 "Authorization: Bearer <token>" 헤더를 constant-time 비교로 검증한다.
//
// 보안 특성:
//   - crypto/subtle.ConstantTimeCompare로 타이밍 공격 방어
//   - 토큰 불일치 시 "Bearer" realm과 함께 401 응답
func BearerTokenMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 토큰 미설정 시 기존 동작 유지
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Authorization 헤더에서 Bearer 토큰 추출
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ebpf-nat"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		provided := strings.TrimPrefix(authHeader, "Bearer ")

		// 상수 시간 비교로 타이밍 공격 방어
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ebpf-nat"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
