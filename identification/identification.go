package identification

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
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

	header := c.GetHeader("token")
	if header == "" {
		handleError(c, http.StatusOK, "Token not found", nil)
		c.Abort()
		return
	}

	// Parse the token with the provided secret key
	token, err := jwt.ParseWithClaims(header, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		handleError(c, http.StatusOK, "Failed to parse token", err)
		c.Abort()
		return
	}

	if !token.Valid {
		handleError(c, http.StatusOK, "Invalid token", err)
		c.Abort()
		return
	}

	// Extract claims from the token
	claims, ok := token.Claims.(*Claims)
	if !ok {
		handleError(c, http.StatusOK, "Failed to extract claims", nil)
		c.Abort()
		return
	}

	if time.Now().Unix() > claims.ExpiresAt {
		handleError(c, http.StatusOK, "Token expired", nil)
		c.Abort()
		return
	}

	fmt.Println("Username: ")
	fmt.Println(claims.UserName)
	c.Set("user_name", claims.UserName)
	c.Next()
}

func TestMiddleware(c *gin.Context) {
	fmt.Println("Test Middleware: ")
	c.Next()
}

func Test() {
	fmt.Println("Tests pc:")
}
