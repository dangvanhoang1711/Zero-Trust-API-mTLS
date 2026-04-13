package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type responseBody map[string]string

func main() {
	forceAllow := os.Getenv("FORCE_ALLOW_FOR_DEMO") == "true"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleAuth(w, r, forceAllow)
	})

	log.Println("--- PDP SERVER ĐANG CHẠY TRÊN PORT 5000 ---")
	if err := http.ListenAndServe(":5000", handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}

func handleAuth(w http.ResponseWriter, r *http.Request, forceAllow bool) {
	log.Println("\n[PDP] >>> Đã nhận yêu cầu!")
	authHeader := r.Header.Get("Authorization")
	log.Printf("    + Header nhận được: %s", authHeader)

	if authHeader == "" {
		log.Println("[PDP] <<< KẾT QUẢ: CHẶN (Vì Header Authorization đang trống rỗng)")
		writeJSON(w, http.StatusUnauthorized, responseBody{"status": "Missing Header"})
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[1] == "" {
		log.Println("[PDP] <<< LỖI: Invalid authorization header format")
		writeJSON(w, http.StatusForbidden, responseBody{"status": "Denied", "reason": "Invalid Token Format"})
		return
	}

	payload, err := decodeToken(parts[1])
	if err != nil {
		log.Printf("[PDP] <<< LỖI: %v", err)
		writeJSON(w, http.StatusForbidden, responseBody{"status": "Denied", "reason": "Invalid Token Format"})
		return
	}

	isAllowed, message := verifyZeroTrustPolicy(payload)

	if forceAllow {
		log.Println("[PDP] !!! CHẾ ĐỘ DEMO ĐANG BẬT: Bỏ qua lỗi và cho phép truy cập.")
		writeJSON(w, http.StatusOK, responseBody{"status": "OK", "info": "Demo Mode"})
		return
	}

	if isAllowed {
		log.Printf("[PDP] <<< KẾT QUẢ: CHO QUA. (%s)", message)
		writeJSON(w, http.StatusOK, responseBody{"status": "OK"})
		return
	}

	log.Printf("[PDP] <<< KẾT QUẢ: TỪ CHỐI. (%s)", message)
	writeJSON(w, http.StatusForbidden, responseBody{"status": "Forbidden", "reason": message})
}

func decodeToken(rawToken string) (jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected token claims")
	}

	return claims, nil
}

func verifyZeroTrustPolicy(payload jwt.MapClaims) (bool, string) {
	userClearance, _ := payload["clearance"].(string)
	allowedHours, _ := payload["allowed_hours"].(string)
	username, _ := payload["preferred_username"].(string)
	if username == "" {
		username = "Unknown"
	}

	currentHour := time.Now().Hour()

	log.Printf("--- [DEBUG] Kiểm tra User: %s ---", username)
	log.Printf("    + Clearance trong Token: %s", userClearance)
	log.Printf("    + Giờ cho phép trong Token: %s", allowedHours)
	log.Printf("    + Giờ hệ thống lúc này: %dh", currentHour)

	if userClearance == "" || allowedHours == "" {
		return false, "Thiếu trường 'clearance' hoặc 'allowed_hours' trong Token (Cần check Keycloak)"
	}

	rangeParts := strings.SplitN(allowedHours, "-", 2)
	if len(rangeParts) != 2 {
		return false, "Lỗi định dạng giờ: invalid range"
	}

	startHour, err := strconv.Atoi(rangeParts[0])
	if err != nil {
		return false, fmt.Sprintf("Lỗi định dạng giờ: %v", err)
	}

	endHour, err := strconv.Atoi(rangeParts[1])
	if err != nil {
		return false, fmt.Sprintf("Lỗi định dạng giờ: %v", err)
	}

	if userClearance == "action1" && startHour <= currentHour && currentHour <= endHour {
		return true, fmt.Sprintf("Hợp lệ! Chào mừng %s.", username)
	}

	return false, fmt.Sprintf("Vi phạm Policy: Clearance=%s, Giờ hiện tại=%dh", userClearance, currentHour)
}

func writeJSON(w http.ResponseWriter, status int, body responseBody) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}
