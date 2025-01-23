package validator

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Common validation errors
var (
	ErrInvalidKey      = errors.New("invalid API key")
	ErrValidationError = errors.New("validation error")
	ErrRateLimited     = errors.New("rate limit exceeded")
	ErrTimeout         = errors.New("validation timeout")
	ErrServiceDown     = errors.New("service unavailable")
)

// ValidationMethod defines how the validation is performed
type ValidationMethod string

const (
	MethodSDK  ValidationMethod = "sdk"
	MethodHTTP ValidationMethod = "http"
)

// RiskLevel represents the risk assessment of an API key
type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

// ValidationResult represents the outcome of key validation
type ValidationResult struct {
	Valid       bool                   `json:"valid"`
	Service     string                 `json:"service"`
	Permissions []string               `json:"permissions,omitempty"`
	RiskLevel   RiskLevel              `json:"risk_level"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Error       error                  `json:"-"`
	ErrorStr    string                 `json:"error,omitempty"`
	ValidatedAt time.Time              `json:"validated_at"`
}

// Validator interface defines the contract for service-specific validators
type Validator interface {
	// Validate performs the validation of an API key
	Validate(ctx context.Context, key string) (*ValidationResult, error)

	// GetService returns the name of the service this validator handles
	GetService() string

	// GetValidationMethod returns whether this validator uses SDK or HTTP
	GetValidationMethod() ValidationMethod
}

// ValidationManager handles the validation process across multiple services
type ValidationManager struct {
	validators map[string]Validator
	client     *http.Client
	mu         sync.RWMutex
}

// NewValidationManager creates a new validation manager
func NewValidationManager() *ValidationManager {
	return &ValidationManager{
		validators: make(map[string]Validator),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// RegisterValidator adds a new validator to the manager
func (vm *ValidationManager) RegisterValidator(v Validator) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.validators[v.GetService()] = v
}

// GetValidator retrieves a validator for a specific service
func (vm *ValidationManager) GetValidator(service string) (Validator, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	v, exists := vm.validators[service]
	return v, exists
}

// ValidateKey validates a single key for a specific service
func (vm *ValidationManager) ValidateKey(ctx context.Context, service, key string) (*ValidationResult, error) {
	validator, exists := vm.GetValidator(service)
	if !exists {
		return nil, errors.New("no validator found for service: " + service)
	}

	result, err := validator.Validate(ctx, key)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// ValidateKeysParallel validates multiple keys in parallel
func (vm *ValidationManager) ValidateKeysParallel(ctx context.Context, service string, keys []string) []*ValidationResult {
	results := make([]*ValidationResult, len(keys))
	var wg sync.WaitGroup

	// Create a buffered channel to limit concurrent validations
	semaphore := make(chan struct{}, 5) // Max 5 concurrent validations

	for i, key := range keys {
		wg.Add(1)
		go func(index int, apiKey string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, err := vm.ValidateKey(ctx, service, apiKey)
			if err != nil {
				results[index] = &ValidationResult{
					Valid:       false,
					Service:     service,
					Error:       err,
					ErrorStr:    err.Error(),
					ValidatedAt: time.Now(),
				}
				return
			}
			results[index] = result
		}(i, key)
	}

	wg.Wait()
	return results
}

// GetSupportedServices returns a list of services that can be validated
func (vm *ValidationManager) GetSupportedServices() []string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	services := make([]string, 0, len(vm.validators))
	for service := range vm.validators {
		services = append(services, service)
	}
	return services
}
