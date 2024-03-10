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

	// Attempt to bind the JSON body to a struct
	var body struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		handleError(c, http.StatusBadRequest, "Failed to parse request body", err)
		c.Abort()
		return
	}

	tokenString := body.Token

	// Parse the token with the provided secret key
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		handleError(c, http.StatusUnauthorized, "Failed to parse token", err)
		c.Abort()
		return
	}

	if !token.Valid {
		handleError(c, http.StatusBadRequest, "Invalid token", err)
		c.Abort()
		return
	}

	// Extract claims from the token
	claims, ok := token.Claims.(*Claims)
	if !ok {
		handleError(c, http.StatusInternalServerError, "Failed to extract claims", nil)
		c.Abort()
		return
	}

	if time.Now().Unix() > claims.ExpiresAt {
		handleError(c, http.StatusUnauthorized, "Token expired", nil)
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
