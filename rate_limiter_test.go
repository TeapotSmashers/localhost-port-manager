package main

import (
	"log"
	"os"
	"sync"
	"testing"
	"time"
)

// TestIPRateLimiter_Basic tests basic rate limiting functionality
func TestIPRateLimiter_Basic(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	// Create rate limiter with 2 RPS and burst of 3
	rateLimiter := NewIPRateLimiter(2, 3, structuredLogger)

	clientIP := "192.168.1.1"

	// First 3 requests should be allowed (burst)
	for i := 0; i < 3; i++ {
		if !rateLimiter.Allow(clientIP) {
			t.Errorf("Request %d should be allowed (within burst limit)", i+1)
		}
	}

	// 4th request should be denied (burst exhausted)
	if rateLimiter.Allow(clientIP) {
		t.Error("4th request should be denied (burst exhausted)")
	}
}

// TestIPRateLimiter_TokenRefill tests token refill over time
func TestIPRateLimiter_TokenRefill(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	// Create rate limiter with 2 RPS and burst of 2
	rateLimiter := NewIPRateLimiter(2, 2, structuredLogger)

	clientIP := "192.168.1.2"

	// Exhaust the burst
	for i := 0; i < 2; i++ {
		if !rateLimiter.Allow(clientIP) {
			t.Errorf("Request %d should be allowed (within burst limit)", i+1)
		}
	}

	// Next request should be denied
	if rateLimiter.Allow(clientIP) {
		t.Error("Request should be denied (burst exhausted)")
	}

	// Wait for 1 second (should refill 2 tokens at 2 RPS)
	time.Sleep(1100 * time.Millisecond)

	// Should be able to make 2 more requests
	for i := 0; i < 2; i++ {
		if !rateLimiter.Allow(clientIP) {
			t.Errorf("Request %d should be allowed after token refill", i+1)
		}
	}

	// Next request should be denied again
	if rateLimiter.Allow(clientIP) {
		t.Error("Request should be denied after consuming refilled tokens")
	}
}

// TestIPRateLimiter_MultipleIPs tests rate limiting for multiple IP addresses
func TestIPRateLimiter_MultipleIPs(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	// Create rate limiter with 1 RPS and burst of 1
	rateLimiter := NewIPRateLimiter(1, 1, structuredLogger)

	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// Each IP should be able to make 1 request (burst)
	if !rateLimiter.Allow(ip1) {
		t.Error("First request from IP1 should be allowed")
	}
	if !rateLimiter.Allow(ip2) {
		t.Error("First request from IP2 should be allowed")
	}

	// Second requests should be denied for both IPs
	if rateLimiter.Allow(ip1) {
		t.Error("Second request from IP1 should be denied")
	}
	if rateLimiter.Allow(ip2) {
		t.Error("Second request from IP2 should be denied")
	}
}

// TestIPRateLimiter_Configure tests dynamic configuration changes
func TestIPRateLimiter_Configure(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	// Create rate limiter with 1 RPS and burst of 1
	rateLimiter := NewIPRateLimiter(1, 1, structuredLogger)

	clientIP := "192.168.1.1"

	// Use up the initial burst
	if !rateLimiter.Allow(clientIP) {
		t.Error("Initial request should be allowed")
	}
	if rateLimiter.Allow(clientIP) {
		t.Error("Second request should be denied")
	}

	// Reconfigure to higher limits
	rateLimiter.Configure(5, 3)

	// Should now be able to make more requests due to higher burst
	for i := 0; i < 3; i++ {
		if !rateLimiter.Allow(clientIP) {
			t.Errorf("Request %d should be allowed after reconfiguration", i+1)
		}
	}

	// Next request should be denied
	if rateLimiter.Allow(clientIP) {
		t.Error("Request should be denied after consuming new burst")
	}
}

// TestIPRateLimiter_Cleanup tests the cleanup functionality
func TestIPRateLimiter_Cleanup(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	rateLimiter := NewIPRateLimiter(1, 1, structuredLogger)

	// Make requests from multiple IPs to create entries
	ips := []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}
	for _, ip := range ips {
		rateLimiter.Allow(ip)
	}

	// Check that entries exist
	rateLimiter.mutex.RLock()
	initialCount := len(rateLimiter.limiters)
	rateLimiter.mutex.RUnlock()

	if initialCount != 3 {
		t.Errorf("Expected 3 entries, got %d", initialCount)
	}

	// Cleanup should not remove recent entries
	rateLimiter.Cleanup()

	rateLimiter.mutex.RLock()
	afterCleanupCount := len(rateLimiter.limiters)
	rateLimiter.mutex.RUnlock()

	if afterCleanupCount != 3 {
		t.Errorf("Expected 3 entries after cleanup (entries are recent), got %d", afterCleanupCount)
	}
}

// TestIPRateLimiter_ConcurrentAccess tests thread safety
func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	rateLimiter := NewIPRateLimiter(10, 5, structuredLogger)

	var wg sync.WaitGroup
	var allowedCount int32
	var deniedCount int32
	var mutex sync.Mutex

	// Launch multiple goroutines making requests
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			clientIP := "192.168.1.1" // Same IP for all requests

			for j := 0; j < 10; j++ {
				if rateLimiter.Allow(clientIP) {
					mutex.Lock()
					allowedCount++
					mutex.Unlock()
				} else {
					mutex.Lock()
					deniedCount++
					mutex.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()

	// Should have some allowed and some denied requests
	if allowedCount == 0 {
		t.Error("Expected some requests to be allowed")
	}
	if deniedCount == 0 {
		t.Error("Expected some requests to be denied")
	}

	totalRequests := allowedCount + deniedCount
	if totalRequests != 100 {
		t.Errorf("Expected 100 total requests, got %d", totalRequests)
	}
}

// TestTokenBucket_Refill tests the token bucket refill mechanism
func TestTokenBucket_Refill(t *testing.T) {
	bucket := &TokenBucket{
		tokens:     0,
		maxTokens:  5,
		lastRefill: time.Now().Add(-2 * time.Second), // 2 seconds ago
	}

	// Refill with 3 RPS should add 6 tokens (2 seconds * 3 RPS)
	bucket.refill(3)

	if bucket.tokens != 5 { // Should be capped at maxTokens
		t.Errorf("Expected 5 tokens (capped), got %d", bucket.tokens)
	}
}

// TestTokenBucket_Consume tests token consumption
func TestTokenBucket_Consume(t *testing.T) {
	bucket := &TokenBucket{
		tokens:     3,
		maxTokens:  5,
		lastRefill: time.Now(),
	}

	// Should be able to consume 3 tokens
	for i := 0; i < 3; i++ {
		if !bucket.consume(1) {
			t.Errorf("Should be able to consume token %d", i+1)
		}
	}

	// Should not be able to consume more
	if bucket.consume(1) {
		t.Error("Should not be able to consume when no tokens available")
	}

	if bucket.tokens != 0 {
		t.Errorf("Expected 0 tokens remaining, got %d", bucket.tokens)
	}
}

// TestRateLimiter_Integration tests integration with WebServiceHandler
func TestRateLimiter_Integration(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	// Create config with rate limiting enabled
	config := &Config{
		EnableRateLimit: true,
		RateLimitRPS:    2,
		DeploymentConfig: &DeploymentConfig{
			WebConfig: &WebServiceConfig{
				RateLimit: struct {
					Enabled bool `json:"enabled"`
					RPS     int  `json:"rps"`
					Burst   int  `json:"burst"`
				}{
					Enabled: true,
					RPS:     2,
					Burst:   3,
				},
			},
		},
	}

	// Create domain matcher
	domainMatcher := NewPatternMatcher(structuredLogger)
	domainMatcher.AddPattern("*.example.com")

	// Create security validator
	securityValidator := NewSecurityValidator(structuredLogger)

	// Create web service handler
	handler := NewWebServiceHandler(domainMatcher, config, structuredLogger, securityValidator)

	// Verify rate limiter is created
	if handler.rateLimiter == nil {
		t.Error("Rate limiter should be created when rate limiting is enabled")
	}

	// Test that rate limiter works
	clientIP := "192.168.1.1"

	// First few requests should be allowed (burst)
	for i := 0; i < 3; i++ {
		if !handler.rateLimiter.Allow(clientIP) {
			t.Errorf("Request %d should be allowed (within burst)", i+1)
		}
	}

	// Next request should be denied
	if handler.rateLimiter.Allow(clientIP) {
		t.Error("Request should be denied (burst exhausted)")
	}
}

// TestRateLimiter_Disabled tests that rate limiter is not created when disabled
func TestRateLimiter_Disabled(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST] ", log.LstdFlags)
	structuredLogger := NewStructuredLogger(logger)

	// Create config with rate limiting disabled
	config := &Config{
		EnableRateLimit: false,
	}

	// Create domain matcher
	domainMatcher := NewPatternMatcher(structuredLogger)
	domainMatcher.AddPattern("*.example.com")

	// Create security validator
	securityValidator := NewSecurityValidator(structuredLogger)

	// Create web service handler
	handler := NewWebServiceHandler(domainMatcher, config, structuredLogger, securityValidator)

	// Verify rate limiter is not created
	if handler.rateLimiter != nil {
		t.Error("Rate limiter should not be created when rate limiting is disabled")
	}
}
