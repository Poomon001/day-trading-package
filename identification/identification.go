package identification

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

var secretKey = []byte("secret")

type ErrorResponse struct {
	Success bool              `json:"success"`
	Data    map[string]string `json:"data"`
}

type Claims struct {
	UserName string `json:"user_name"`
	jwt.StandardClaims
}

func handleError(c *gin.Context, statusCode int, message string, err error) {
	errorResponse := ErrorResponse{
		Success: false,
		Data:    map[string]string{"error": message},
	}
	c.IndentedJSON(statusCode, errorResponse)
}

func Identification(c *gin.Context) {
	fmt.Println("Identification Middleware:")

	// Retrieve token from the cookie
	cookie, err := c.Cookie("token")
	if err != nil {
		handleError(c, http.StatusBadRequest, "Failed to retrieve session token from cookie", err)
		c.Abort()
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			handleError(c, http.StatusBadRequest, "Unauthorized Access", err)
			c.Abort()
			return
		}
		handleError(c, http.StatusBadRequest, "Failed to parse claims", err)
		c.Abort()
		return
	}

	if !token.Valid {
		handleError(c, http.StatusBadRequest, "Invalid token", err)
		c.Abort()
		return
	}

	// Check token expiry
	if time.Now().Unix() > claims.ExpiresAt {
		handleError(c, http.StatusUnauthorized, "Token expired", nil)
		c.Abort()
		return
	}

	fmt.Println(claims.ExpiresAt)
	fmt.Println(claims.UserName)
	c.Set("user_name", claims.UserName)
	c.Next()
}

func TestMiddleware(c *gin.Context) {
	fmt.Println("Test Middleware: ")
	c.Next()
}

func Test() {
	fmt.Println("Tests:")
}
