package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	
	"github.com/mesikahq/hipaa-exchange/internal/audit"
)

func main() {
	// Load configuration
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	// Set Gin mode
	gin.SetMode(viper.GetString("server.mode"))

	// Initialize router
	router := gin.New()

	// Add middleware
	router.Use(
		gin.Recovery(),
		// Add security headers middleware
		securityHeaders(),
		// Add CORS middleware
		cors(),
		// Add request ID middleware
		requestID(),
		// Add audit logging middleware
		auditLog(),
	)

	// Initialize server
	srv := &http.Server{
		Addr:         ":" + viper.GetString("server.port"),
		Handler:      router,
		ReadTimeout:  viper.GetDuration("server.timeout"),
		WriteTimeout: viper.GetDuration("server.timeout"),
	}

	// Start server in a goroutine
	go func() {
		if viper.GetBool("server.tls.enabled") {
			if err := srv.ListenAndServeTLS(
				viper.GetString("server.tls.cert_file"),
				viper.GetString("server.tls.key_file"),
			); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Next()
	}
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Authorization, Content-Type")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		uuid := c.GetHeader("X-Request-ID")
		if uuid == "" {
			uuid = generateUUID()
		}
		c.Set("RequestID", uuid)
		c.Header("X-Request-ID", uuid)
		c.Next()
	}
}

func auditLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get request details
		startTime := time.Now()
		requestID := c.GetString("X-Request-ID")
		if requestID == "" {
			requestID = generateUUID()
			c.Set("X-Request-ID", requestID)
		}

		// Get user ID from context (set by auth middleware)
		userID, _ := c.Get("user_id")
		userIDStr, _ := userID.(string)
		if userIDStr == "" {
			userIDStr = "anonymous"
		}

		// Process request
		c.Next()

		// Create audit event
		event := &audit.AuditEvent{
			Timestamp:   startTime,
			EventType:   audit.EventAccess,
			UserID:      userIDStr,
			Action:      c.Request.Method,
			Resource:    c.Request.URL.Path,
			ResourceID:  c.Param("id"), // Get resource ID from URL params if present
			IPAddress:   c.ClientIP(),
			UserAgent:   c.Request.UserAgent(),
			RequestID:   requestID,
			Status:      http.StatusText(c.Writer.Status()),
			Sensitivity: "PHI",
		}

		// Get audit service from the application context
		if auditSvc, exists := c.Get("audit_service"); exists {
			if svc, ok := auditSvc.(audit.Service); ok {
				// Log event asynchronously to not block the response
				go func(evt *audit.AuditEvent) {
					if err := svc.LogEvent(context.Background(), evt); err != nil {
						log.Printf("Failed to log audit event: %v", err)
					}
				}(event)
			}
		}
	}
}

func generateUUID() string {
	return uuid.New().String()
}
