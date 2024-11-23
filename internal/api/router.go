package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mesikahq/hipaa-exchange/internal/auth"
	"github.com/mesikahq/hipaa-exchange/internal/middleware"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type Router struct {
	handler        *Handler
	authMiddleware *auth.Middleware
}

func NewRouter(handler *Handler, authService *auth.Service) *Router {
	return &Router{
		handler:        handler,
		authMiddleware: auth.NewMiddleware(authService),
	}
}

func (r *Router) SetupRouter(logger *zap.Logger) *gin.Engine {
	router := gin.New()

	// Apply global middleware
	router.Use(
		middleware.RequestIDMiddleware(),
		middleware.SecurityHeadersMiddleware(),
		middleware.RecoveryMiddleware(logger),
		middleware.LoggerMiddleware(logger),
		middleware.RateLimitMiddleware(rate.Every(time.Second), 30), // 30 requests per second
		middleware.CORS(), // Update CORS middleware
	)

	// Serve static files (CSS, JS, images, etc.)
	router.Static("/static", "./web/static")

	// Load HTML templates
	router.LoadHTMLGlob("web/templates/*")

	// Public routes
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "HIPAA Compliant Healthcare Portal",
		})
	})

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// API routes
	api := router.Group("/api")
	{
		// Auth routes (public)
		auth := api.Group("/auth")
		{
			auth.POST("/login/email", r.handler.LoginWithEmail)
			auth.POST("/login", r.handler.LoginWithUsername)
			auth.POST("/logout", r.authMiddleware.RequireRoles(), r.handler.Logout)
			auth.GET("/profile", r.authMiddleware.RequireRoles(), r.handler.GetProfile)
		}

		// Protected routes (require authentication)
		protected := api.Group("")
		protected.Use(r.authMiddleware.RequireRoles())
		{
			// Patient routes
			patients := protected.Group("/patients")
			{
				patients.GET("", r.handler.ListPatients)
				patients.POST("", r.handler.RegisterPatient)
				patients.GET("/:id", r.handler.GetPatient)
				patients.PUT("/:id", r.handler.UpdatePatient)
				patients.DELETE("/:id", r.handler.DeletePatient)
			}

			// Care plan routes
			carePlans := protected.Group("/care-plans")
			{
				carePlans.GET("", r.handler.ListCarePlans)
				carePlans.POST("", r.handler.CreateCarePlan)
				carePlans.GET("/:id", r.handler.GetCarePlan)
				carePlans.PUT("/:id", r.handler.UpdateCarePlan)
				carePlans.DELETE("/:id", r.handler.DeleteCarePlan)
			}

			// Provider routes
			providers := protected.Group("/providers")
			{
				providers.GET("", r.handler.ListProviders)
				providers.POST("", r.handler.RegisterProvider)
				providers.GET("/:id", r.handler.GetProvider)
				providers.PUT("/:id", r.handler.UpdateProvider)
				providers.DELETE("/:id", r.handler.DeactivateProvider)
			}

			// Dashboard routes
			dashboard := protected.Group("/dashboard")
			{
				dashboard.GET("/stats", r.handler.GetDashboardStats)
				dashboard.GET("/activities", r.handler.GetRecentActivities)
				dashboard.GET("/compliance", r.handler.GetComplianceMetrics)
			}

			// Consent routes
			consents := protected.Group("/consents")
			{
				consents.GET("", r.handler.GetConsents)
				consents.POST("", r.handler.CreateConsent)
				consents.GET("/:id", r.handler.GetConsent)
				consents.PUT("/:id", r.handler.UpdateConsent)
				consents.DELETE("/:id", r.handler.RevokeConsent)
			}

			// User profile and settings
			user := protected.Group("/user")
			{
				user.GET("/profile", r.handler.GetUserProfile)
				user.PUT("/profile", r.handler.UpdateUserProfile)
				user.PUT("/password", r.handler.ChangePassword)
				user.POST("/mfa/enable", r.handler.EnableMFA)
				user.POST("/mfa/disable", r.handler.DisableMFA)
			}

			// Audit log routes (admin only)
			audit := protected.Group("/audit")
			audit.Use(r.authMiddleware.RequireRoles("admin"))
			{
				audit.GET("/logs", r.handler.GetAuditLogs)
				audit.GET("/logs/:id", r.handler.GetAuditLog)
			}
		}
	}

	// NoRoute handler for 404
	router.NoRoute(func(c *gin.Context) {
		if c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API endpoint not found"})
			return
		}
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"title": "Page Not Found",
		})
	})

	return router
}
