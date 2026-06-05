package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"jwt-auth-broker/auth"
)

// token validation
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// step1 get the token from request header
		authHeader := r.Header.Get("Authorization")
		// step2 check if header exists
		if authHeader == "" {
			http.Error(w, "Missing auth header", http.StatusUnauthorized)
			return
		}
		// step3 extract token from bearer
		parts := strings.Split(authHeader, " ")
		if len(parts) !=2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
		}

		tokenString := parts[1]
		// step4 validate using auth package
		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or token is expired", http.StatusUnauthorized)
		}
		// step5 print token is valid
		fmt.printf("Token is Valid! User: %s (ID: %s)\n", claims.Username, claims.UserID)

		// ste6 allow the endpoint to executre
	}

}