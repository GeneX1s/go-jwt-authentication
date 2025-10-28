Ah, got it! Here's the **JWT Authentication with Gin** tutorial in **Markdown format** as a `.md` file:

````markdown
# JWT Authentication with Gin (Go)

This tutorial demonstrates how to implement JWT Authentication in a Go application using the **Gin** framework. The steps include creating a login route that generates a JWT token, protecting routes with middleware, and creating a secure endpoint that requires authentication.

## Table of Contents

1. [Install Dependencies](#install-dependencies)
2. [JWT Authentication Logic](#jwt-authentication-logic)
3. [Run the Application](#run-the-application)
4. [Test the Application](#test-the-application)
5. [Enhancements](#enhancements)

---

### Install Dependencies

Before starting, you'll need to install the necessary Go libraries. Run the following commands in your terminal:

```bash
go get github.com/gin-gonic/gin
go get github.com/dgrijalva/jwt-go
go get github.com/spf13/viper
```
````

- **Gin**: A web framework for Go.
- **jwt-go**: A package to work with JSON Web Tokens (JWT).

---

### JWT Authentication Logic

Here is the full code that demonstrates how to generate JWT tokens, protect routes using middleware, and verify the token.

```go
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
```

---

### Explanation of the Code

#### 1. **GenerateJWT Function**

- Generates a JWT token using the provided username.
- The token is signed with a secret key (`my_secret_key`) and is valid for 24 hours.

#### 2. **TokenAuthMiddleware**

- This middleware checks if the request contains a valid JWT token in the `Authorization` header.
- If the token is valid, it extracts the username from the token and makes it available in the context.
- If the token is invalid or missing, it responds with a `401 Unauthorized` status.

#### 3. **Login Route**

- The `/login` route accepts a `POST` request with `username` and `password` in the body.
- If the credentials match the hardcoded values (`admin`/`password123`), a JWT token is generated and returned.

#### 4. **Protected Route**

- The `/protected` route is a secure endpoint that requires a valid JWT token for access.
- The `TokenAuthMiddleware` is used to verify the token, and if valid, the username extracted from the token is returned.

---

### Run the Application

1. **Run the Go application**:

   ```bash
   go run main.go
   ```

2. **Login to get a JWT token**:

   - Make a `POST` request to `http://localhost:8080/login` with a JSON body:

   ```json
   {
     "username": "admin",
     "password": "password123"
   }
   ```

   - If the credentials are correct, you’ll get a response like this:

   ```json
   {
     "message": "Login successful",
     "token": "your_jwt_token_here"
   }
   ```

3. **Access a protected route**:

   - Make a `GET` request to `http://localhost:8080/protected` with the `Authorization` header set to `Bearer <your_jwt_token_here>`.

   ```bash
   curl -H "Authorization: Bearer <your_jwt_token_here>" http://localhost:8080/protected
   ```

   - If the token is valid, you’ll get a response like this:

   ```json
   {
     "message": "This is a protected route",
     "user": "admin"
   }
   ```

   - If the token is invalid or missing, you'll get a `401 Unauthorized` response.

---

### Enhancements

- **User Authentication**: Replace the hardcoded username/password with a database-backed authentication system.
- **Token Expiry**: Extend functionality to refresh expired tokens using refresh tokens.
- **Secure Storage**: Store the secret key in environment variables or a secure vault instead of hardcoding it in the code.
- **Error Handling**: Enhance error handling for different scenarios (invalid JSON input, missing headers, etc.).

---

This should give you a complete working example of JWT Authentication in a Go app using Gin. Let me know if you need further clarification or help with any part of it!

```

---

You can copy this `.md` code and save it as a `.md` file (e.g., `jwt-auth-gin.md`). Let me know if you'd like any further adjustments!
```
