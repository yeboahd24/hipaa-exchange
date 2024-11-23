package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Middleware struct {
	service Service
}

func NewMiddleware(service *Service) *Middleware {
	return &Middleware{
		service: *service,
	}
}

// RequireRoles creates a middleware that checks if the user has the required roles
func (m *Middleware) RequireRoles(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the token from the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no authorization header"})
			c.Abort()
			return
		}

		// If no roles are specified, just validate the token
		if len(requiredRoles) == 0 {
			// Validate token without checking specific roles
			_, err := m.service.ValidateToken(c.Request.Context(), strings.TrimPrefix(authHeader, "Bearer "))
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				c.Abort()
				return
			}
			c.Next()
			return
		}

		// Existing role-based validation logic
		tokenClaims, err := m.service.ValidateToken(c.Request.Context(), strings.TrimPrefix(authHeader, "Bearer "))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Check if the user has any of the required roles
		userRoles := tokenClaims.Roles
		hasRequiredRole := false
		for _, requiredRole := range requiredRoles {
			for _, userRole := range userRoles {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		// Set user context for downstream handlers
		c.Set("user_id", tokenClaims.UserID)
		c.Set("username", tokenClaims.Username)
		c.Set("roles", tokenClaims.Roles)

		c.Next()
	}
}

// GetUserID retrieves the user ID from the gin context
func GetUserID(c *gin.Context) string {
	userID, _ := c.Get("user_id")
	return userID.(string)
}

// GetUserRoles retrieves the user roles from the gin context
func GetUserRoles(c *gin.Context) []string {
	roles, _ := c.Get("roles")
	return roles.([]string)
}
