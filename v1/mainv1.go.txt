package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Secret key to sign the JWT token (use a more secure key in production)
var jwtKey = []byte("my_secret_key")

// User represents the data structure for a user
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims represents the structure of JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// GenerateJWT generates a JWT token for a given user
func GenerateJWT(username string) (string, error) {
	// Create the JWT claims
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
			Issuer:    "myapp",
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	return token.SignedString(jwtKey)
}

// Middleware to check if the request has a valid JWT token
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// The header should be in the form "Bearer <token>"
		tokenString := authHeader[7:]

		// Parse and validate the JWT token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// If valid, set the claims in the context
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			c.Set("username", claims.Username)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	}
}

// Main function to set up routes and Gin server
func main() {
	r := gin.Default()

	// Public route to log in and get a JWT token
	r.POST("/login", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Example authentication: hardcoded username/password check
		if user.Username != "admin" || user.Password != "password123" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// Generate JWT token if credentials are valid
		token, err := GenerateJWT(user.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
			return
		}

		// Respond with the JWT token
		c.JSON(http.StatusOK, gin.H{
			"message": "Login successful",
			"token":   token,
		})
	})

	// Protected route that requires JWT authentication
	r.GET("/protected", TokenAuthMiddleware(), func(c *gin.Context) {
		// Get the username from the context set by the middleware
		username, _ := c.Get("username")

		c.JSON(http.StatusOK, gin.H{
			"message": "This is a protected route",
			"user":    username,
		})
	})

	// Run the server
	r.Run(":8080")
}
