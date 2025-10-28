package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// Secret key to sign the JWT token (use environment variable in production)
var jwtKey = []byte("my_secret_key")

// ============================================================================
// Data Structures
// ============================================================================

// User represents the data structure for a user
type User struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
	Email    string   `json:"email"`
	Active   bool     `json:"active"`
}

// Claims represents the structure of JWT claims with RBAC information
type Claims struct {
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	jwt.StandardClaims
}

// Permission represents a single permission
type Permission string

// Define permission constants
const (
	PermissionReadUsers    Permission = "users:read"
	PermissionWriteUsers   Permission = "users:write"
	PermissionDeleteUsers  Permission = "users:delete"
	PermissionReadReports  Permission = "reports:read"
	PermissionWriteReports Permission = "reports:write"
	PermissionManageRoles  Permission = "roles:manage"
	PermissionViewAudit    Permission = "audit:view"
	PermissionAdminAccess  Permission = "admin:access"
)

// Role represents a role with associated permissions
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	Timestamp  time.Time `json:"timestamp"`
	Username   string    `json:"username"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	Success    bool      `json:"success"`
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	Details    string    `json:"details"`
}

// ============================================================================
// RBAC Configuration
// ============================================================================

// Define roles and their permissions
var roles = map[string]Role{
	"admin": {
		Name:        "admin",
		Description: "Full system administrator",
		Permissions: []Permission{
			PermissionReadUsers,
			PermissionWriteUsers,
			PermissionDeleteUsers,
			PermissionReadReports,
			PermissionWriteReports,
			PermissionManageRoles,
			PermissionViewAudit,
			PermissionAdminAccess,
		},
	},
	"manager": {
		Name:        "manager",
		Description: "Manager with reporting capabilities",
		Permissions: []Permission{
			PermissionReadUsers,
			PermissionReadReports,
			PermissionWriteReports,
			PermissionViewAudit,
		},
	},
	"operator": {
		Name:        "operator",
		Description: "Standard operator",
		Permissions: []Permission{
			PermissionReadUsers,
			PermissionReadReports,
		},
	},
	"viewer": {
		Name:        "viewer",
		Description: "Read-only access",
		Permissions: []Permission{
			PermissionReadReports,
		},
	},
}

// Mock user database (replace with real database in production)
var users = map[string]User{
	"admin": {
		Username: "admin",
		Password: "admin123", // In production, use bcrypt hashed passwords
		Roles:    []string{"admin"},
		Email:    "admin@example.com",
		Active:   true,
	},
	"manager": {
		Username: "manager",
		Password: "manager123",
		Roles:    []string{"manager"},
		Email:    "manager@example.com",
		Active:   true,
	},
	"operator": {
		Username: "operator",
		Password: "operator123",
		Roles:    []string{"operator"},
		Email:    "operator@example.com",
		Active:   true,
	},
	"viewer": {
		Username: "viewer",
		Password: "viewer123",
		Roles:    []string{"viewer"},
		Email:    "viewer@example.com",
		Active:   true,
	},
}

// Audit log storage (use database in production)
var auditLogs []AuditLog

// ============================================================================
// RBAC Functions
// ============================================================================

// GetUserPermissions retrieves all permissions for a user based on their roles
func GetUserPermissions(userRoles []string) []Permission {
	permissionSet := make(map[Permission]bool)
	
	for _, roleName := range userRoles {
		if role, exists := roles[roleName]; exists {
			for _, perm := range role.Permissions {
				permissionSet[perm] = true
			}
		}
	}
	
	permissions := make([]Permission, 0, len(permissionSet))
	for perm := range permissionSet {
		permissions = append(permissions, perm)
	}
	
	return permissions
}

// HasPermission checks if a user has a specific permission
func HasPermission(userPermissions []Permission, required Permission) bool {
	for _, perm := range userPermissions {
		if perm == required {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if a user has any of the required permissions
func HasAnyPermission(userPermissions []Permission, required []Permission) bool {
	for _, reqPerm := range required {
		if HasPermission(userPermissions, reqPerm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if a user has all required permissions
func HasAllPermissions(userPermissions []Permission, required []Permission) bool {
	for _, reqPerm := range required {
		if !HasPermission(userPermissions, reqPerm) {
			return false
		}
	}
	return true
}

// ============================================================================
// JWT Functions
// ============================================================================

// GenerateJWT generates a JWT token for a given user with roles and permissions
func GenerateJWT(user User) (string, error) {
	permissions := GetUserPermissions(user.Roles)
	
	// Convert permissions to strings
	permStrings := make([]string, len(permissions))
	for i, perm := range permissions {
		permStrings[i] = string(perm)
	}
	
	// Create the JWT claims
	claims := &Claims{
		Username:    user.Username,
		Roles:       user.Roles,
		Permissions: permStrings,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 8).Unix(), // Token expires in 8 hours
			IssuedAt:  time.Now().Unix(),
			Issuer:    "rbac-app",
			Subject:   user.Username,
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	return token.SignedString(jwtKey)
}

// ============================================================================
// Audit Logging
// ============================================================================

// LogAudit logs an action to the audit trail
func LogAudit(c *gin.Context, action, resource string, success bool, details string) {
	username := "anonymous"
	if user, exists := c.Get("username"); exists {
		username = user.(string)
	}
	
	log := AuditLog{
		Timestamp:  time.Now(),
		Username:   username,
		Action:     action,
		Resource:   resource,
		Success:    success,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
		Details:    details,
	}
	
	auditLogs = append(auditLogs, log)
	
	// In production, persist to database
	fmt.Printf("[AUDIT] %s | %s | %s | %s | Success: %v\n", 
		log.Timestamp.Format(time.RFC3339), 
		log.Username, 
		log.Action, 
		log.Resource, 
		log.Success)
}

// ============================================================================
// Middleware
// ============================================================================

// TokenAuthMiddleware validates JWT token and extracts user information
func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			LogAudit(c, "AUTH_FAILED", "token", false, "Missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// The header should be in the form "Bearer <token>"
		if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			LogAudit(c, "AUTH_FAILED", "token", false, "Invalid authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}
		
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
			LogAudit(c, "AUTH_FAILED", "token", false, fmt.Sprintf("Invalid token: %v", err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// If valid, set the claims in the context
		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			// Check if user is still active
			if user, exists := users[claims.Username]; !exists || !user.Active {
				LogAudit(c, "AUTH_FAILED", "token", false, "User inactive or not found")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is inactive"})
				c.Abort()
				return
			}
			
			c.Set("username", claims.Username)
			c.Set("roles", claims.Roles)
			c.Set("permissions", claims.Permissions)
		} else {
			LogAudit(c, "AUTH_FAILED", "token", false, "Invalid token claims")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
	}
}

// RequirePermission middleware checks if user has required permission
func RequirePermission(required Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("permissions")
		if !exists {
			LogAudit(c, "ACCESS_DENIED", string(required), false, "No permissions in context")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}
		
		permStrings := permissions.([]string)
		userPerms := make([]Permission, len(permStrings))
		for i, p := range permStrings {
			userPerms[i] = Permission(p)
		}
		
		if !HasPermission(userPerms, required) {
			username, _ := c.Get("username")
			LogAudit(c, "ACCESS_DENIED", string(required), false, 
				fmt.Sprintf("User %s lacks permission: %s", username, required))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"required_permission": required,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// RequireAnyPermission middleware checks if user has any of the required permissions
func RequireAnyPermission(required []Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		permissions, exists := c.Get("permissions")
		if !exists {
			LogAudit(c, "ACCESS_DENIED", "multiple", false, "No permissions in context")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}
		
		permStrings := permissions.([]string)
		userPerms := make([]Permission, len(permStrings))
		for i, p := range permStrings {
			userPerms[i] = Permission(p)
		}
		
		if !HasAnyPermission(userPerms, required) {
			username, _ := c.Get("username")
			LogAudit(c, "ACCESS_DENIED", "multiple", false, 
				fmt.Sprintf("User %s lacks any required permission", username))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"required_any_of": required,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// RequireRole middleware checks if user has required role
func RequireRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("roles")
		if !exists {
			LogAudit(c, "ACCESS_DENIED", "role:"+requiredRole, false, "No roles in context")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}
		
		userRoles := roles.([]string)
		hasRole := false
		for _, role := range userRoles {
			if role == requiredRole {
				hasRole = true
				break
			}
		}
		
		if !hasRole {
			username, _ := c.Get("username")
			LogAudit(c, "ACCESS_DENIED", "role:"+requiredRole, false, 
				fmt.Sprintf("User %s lacks required role: %s", username, requiredRole))
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient role",
				"required_role": requiredRole,
			})
			c.Abort()
			return
		}
		
		c.Next()
	}
}

// ============================================================================
// Route Handlers
// ============================================================================

// Login handler
func loginHandler(c *gin.Context) {
	var credentials User
	if err := c.ShouldBindJSON(&credentials); err != nil {
		LogAudit(c, "LOGIN_FAILED", "auth", false, "Invalid input")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Lookup user
	user, exists := users[credentials.Username]
	if !exists || user.Password != credentials.Password {
		LogAudit(c, "LOGIN_FAILED", "auth", false, 
			fmt.Sprintf("Invalid credentials for user: %s", credentials.Username))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if user is active
	if !user.Active {
		LogAudit(c, "LOGIN_FAILED", "auth", false, 
			fmt.Sprintf("Inactive user attempted login: %s", credentials.Username))
		c.JSON(http.StatusForbidden, gin.H{"error": "User account is inactive"})
		return
	}

	// Generate JWT token
	token, err := GenerateJWT(user)
	if err != nil {
		LogAudit(c, "LOGIN_FAILED", "auth", false, "Token generation failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	LogAudit(c, "LOGIN_SUCCESS", "auth", true, 
		fmt.Sprintf("User %s logged in successfully", user.Username))

	// Respond with the JWT token and user info
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   token,
		"user": gin.H{
			"username": user.Username,
			"roles":    user.Roles,
			"permissions": GetUserPermissions(user.Roles),
		},
	})
}

// Get current user info
func getUserInfoHandler(c *gin.Context) {
	username, _ := c.Get("username")
	roles, _ := c.Get("roles")
	permissions, _ := c.Get("permissions")
	
	LogAudit(c, "VIEW_PROFILE", "user", true, "User viewed own profile")
	
	c.JSON(http.StatusOK, gin.H{
		"username":    username,
		"roles":       roles,
		"permissions": permissions,
	})
}

// List all users (requires admin permission)
func listUsersHandler(c *gin.Context) {
	userList := make([]gin.H, 0, len(users))
	for _, user := range users {
		userList = append(userList, gin.H{
			"username": user.Username,
			"email":    user.Email,
			"roles":    user.Roles,
			"active":   user.Active,
		})
	}
	
	LogAudit(c, "LIST_USERS", "users", true, "User list retrieved")
	
	c.JSON(http.StatusOK, gin.H{
		"users": userList,
		"total": len(userList),
	})
}

// Create user (requires write permission)
func createUserHandler(c *gin.Context) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	
	if _, exists := users[newUser.Username]; exists {
		LogAudit(c, "CREATE_USER_FAILED", "users", false, 
			fmt.Sprintf("User already exists: %s", newUser.Username))
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}
	
	newUser.Active = true
	users[newUser.Username] = newUser
	
	LogAudit(c, "CREATE_USER", "users", true, 
		fmt.Sprintf("Created user: %s with roles: %v", newUser.Username, newUser.Roles))
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user": gin.H{
			"username": newUser.Username,
			"email":    newUser.Email,
			"roles":    newUser.Roles,
		},
	})
}

// Delete user (requires delete permission)
func deleteUserHandler(c *gin.Context) {
	username := c.Param("username")
	
	if _, exists := users[username]; !exists {
		LogAudit(c, "DELETE_USER_FAILED", "users", false, 
			fmt.Sprintf("User not found: %s", username))
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	
	delete(users, username)
	
	LogAudit(c, "DELETE_USER", "users", true, 
		fmt.Sprintf("Deleted user: %s", username))
	
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("User %s deleted successfully", username),
	})
}

// View reports
func viewReportsHandler(c *gin.Context) {
	LogAudit(c, "VIEW_REPORTS", "reports", true, "Reports accessed")
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Reports data",
		"reports": []gin.H{
			{"id": 1, "name": "Monthly Sales", "type": "sales"},
			{"id": 2, "name": "User Activity", "type": "analytics"},
		},
	})
}

// Generate report (requires write permission)
func generateReportHandler(c *gin.Context) {
	type ReportRequest struct {
		ReportType string `json:"report_type" binding:"required"`
		DateRange  string `json:"date_range"`
	}
	
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	
	LogAudit(c, "GENERATE_REPORT", "reports", true, 
		fmt.Sprintf("Generated report: %s", req.ReportType))
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Report generated successfully",
		"report": gin.H{
			"type":      req.ReportType,
			"generated": time.Now(),
			"status":    "completed",
		},
	})
}

// View audit logs (requires audit view permission)
func viewAuditLogsHandler(c *gin.Context) {
	limit := 50
	start := len(auditLogs) - limit
	if start < 0 {
		start = 0
	}
	
	recentLogs := auditLogs[start:]
	
	LogAudit(c, "VIEW_AUDIT", "audit", true, "Audit logs accessed")
	
	c.JSON(http.StatusOK, gin.H{
		"audit_logs": recentLogs,
		"total":      len(auditLogs),
		"showing":    len(recentLogs),
	})
}

// List roles and permissions
func listRolesHandler(c *gin.Context) {
	roleList := make([]gin.H, 0, len(roles))
	for _, role := range roles {
		roleList = append(roleList, gin.H{
			"name":        role.Name,
			"description": role.Description,
			"permissions": role.Permissions,
		})
	}
	
	LogAudit(c, "LIST_ROLES", "roles", true, "Roles list retrieved")
	
	c.JSON(http.StatusOK, gin.H{
		"roles": roleList,
	})
}

// Admin-only dashboard
func adminDashboardHandler(c *gin.Context) {
	LogAudit(c, "ACCESS_ADMIN_DASHBOARD", "admin", true, "Admin dashboard accessed")
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Admin Dashboard",
		"stats": gin.H{
			"total_users":      len(users),
			"total_audit_logs": len(auditLogs),
			"total_roles":      len(roles),
		},
	})
}

// ============================================================================
// Main Function
// ============================================================================

func main() {
	r := gin.Default()

	// Public routes
	public := r.Group("/api/v1")
	{
		public.POST("/login", loginHandler)
	}

	// Protected routes (require authentication)
	protected := r.Group("/api/v1")
	protected.Use(TokenAuthMiddleware())
	{
		// User info
		protected.GET("/me", getUserInfoHandler)
		
		// Reports (read permission required)
		protected.GET("/reports", 
			RequirePermission(PermissionReadReports), 
			viewReportsHandler)
		
		// Generate reports (write permission required)
		protected.POST("/reports", 
			RequirePermission(PermissionWriteReports), 
			generateReportHandler)
	}

	// User management routes
	users := protected.Group("/users")
	{
		// List users (read permission)
		users.GET("", 
			RequirePermission(PermissionReadUsers), 
			listUsersHandler)
		
		// Create user (write permission)
		users.POST("", 
			RequirePermission(PermissionWriteUsers), 
			createUserHandler)
		
		// Delete user (delete permission)
		users.DELETE("/:username", 
			RequirePermission(PermissionDeleteUsers), 
			deleteUserHandler)
	}

	// Admin routes (require admin role)
	admin := protected.Group("/admin")
	admin.Use(RequireRole("admin"))
	{
		admin.GET("/dashboard", adminDashboardHandler)
		
		// Audit logs (requires audit view permission)
		admin.GET("/audit-logs", 
			RequirePermission(PermissionViewAudit), 
			viewAuditLogsHandler)
		
		// Roles management
		admin.GET("/roles", 
			RequirePermission(PermissionManageRoles), 
			listRolesHandler)
	}

	fmt.Println("==============================================")
	fmt.Println("RBAC Server Starting...")
	fmt.Println("==============================================")
	fmt.Println("\nAvailable Test Users:")
	fmt.Println("1. admin/admin123     - Full access")
	fmt.Println("2. manager/manager123 - Manager access")
	fmt.Println("3. operator/operator123 - Operator access")
	fmt.Println("4. viewer/viewer123   - Read-only access")
	fmt.Println("\n==============================================")
	fmt.Println("Server running on http://localhost:8080")
	fmt.Println("==============================================\n")

	// Run the server
	r.Run(":8080")
}