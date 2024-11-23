package middleware

import (
	"context"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mesikahq/hipaa-exchange/internal/auth"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// AuthMiddleware creates a Gin middleware for JWT authentication
func AuthMiddleware(authService auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		// Extract bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
			return
		}

		claims, err := authService.ValidateToken(c.Request.Context(), parts[1])
		if err != nil {
			if err == auth.ErrMFARequired {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "MFA validation required", "mfa_required": true})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("roles", claims.Roles)

		c.Next()
	}
}

// RoleMiddleware creates a Gin middleware for role-based access control
func RoleMiddleware(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userRoles, exists := c.Get("roles")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		roles := userRoles.([]string)
		hasRole := false
		for _, role := range roles {
			for _, required := range requiredRoles {
				if role == required {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}

		c.Next()
	}
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = GenerateRequestID()
		}

		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")

		c.Next()
	}
}

// AuditContextMiddleware adds audit context to all requests
func AuditContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), "request_id", c.GetString("request_id"))
		ctx = context.WithValue(ctx, "ip_address", c.ClientIP())
		ctx = context.WithValue(ctx, "user_agent", c.GetHeader("User-Agent"))
		
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// TimeoutMiddleware adds a timeout to the request context
func TimeoutMiddleware(timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		
		c.Next()

		if ctx.Err() == context.DeadlineExceeded {
			c.AbortWithStatusJSON(http.StatusGatewayTimeout, gin.H{"error": "request timeout"})
			return
		}
	}
}

// RateLimitMiddleware implements rate limiting per IP address
func RateLimitMiddleware(limit rate.Limit, burst int) gin.HandlerFunc {
	limiters := sync.Map{}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		
		limiterI, _ := limiters.LoadOrStore(ip, rate.NewLimiter(limit, burst))
		limiter := limiterI.(*rate.Limiter)

		if !limiter.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		c.Next()
	}
}

// RecoveryMiddleware recovers from panics and logs them
func RecoveryMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				stack := debug.Stack()
				logger.Error("panic recovered",
					zap.Any("error", err),
					zap.ByteString("stack", stack),
					zap.String("request_id", c.GetString("request_id")),
				)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
		}()
		
		c.Next()
	}
}

// LoggerMiddleware creates a logging middleware using zap logger
func LoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()

		// Process request
		c.Next()

		// Log request details
		duration := time.Since(start)
		logger.Info("Request processed",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", duration),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}
