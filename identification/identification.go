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

	const BearerSchema = "Bearer "

	header := c.GetHeader("Authorization")
	if header == "" {
		handleError(c, http.StatusUnauthorized, "Authorization header is missing", nil)
		c.Abort()
		return
	}

	if !strings.HasPrefix(header, BearerSchema) {
		handleError(c, http.StatusUnauthorized, "Invalid authorization header format", nil)
		c.Abort()
		return
	}

	tokenString := header[len(BearerSchema):]
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		handleError(c, http.StatusBadRequest, "Invalid token", err)
		c.Abort()
		return
	}

	if claims, ok := token.Claims.(Claims); ok && token.Valid {
		c.Set("claims", claims)
		c.Next()
	} else {
		handleError(c, http.StatusBadRequest, "Invalid token", err)
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
	fmt.Println("Tests 123:")
}
