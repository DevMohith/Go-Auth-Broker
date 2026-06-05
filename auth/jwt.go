package auth

import (
	"os"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

// jwt data blueprint
type Claims struct {
	UserID string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID string, username string) (string, error) {
	expirationTime := time.Now().Add(2 * time.Minute)

	// claims inside JWT
	claims := &Claims {
		UserID: userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	// creating token with climes
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// sign with secret key
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func GenerateRefreshToken(userID string, username string) (string, error) {
	expirationTime := time.Now().Add(7*24*time.Hour)

	claims := &Claims{
		UserID:  userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	token:= jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}
 

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	//parse tokenm
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	return claims, nil
}