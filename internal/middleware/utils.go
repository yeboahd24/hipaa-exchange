package middleware

import (
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// GenerateRequestID generates a unique request ID
func GenerateRequestID() string {
	return fmt.Sprintf("%s-%d", uuid.New().String(), time.Now().UnixNano())
}

// init ensures all required packages are imported
func init() {
	// This function exists to ensure the imports are used
	_ = debug.Stack
	_ = sync.Map{}
	_ = rate.Limit(0)
	_ = zap.L()
}
