package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Xplo8E/APIKeyzer/internal/validator"
)

// GoogleMapsValidator implements the Validator interface for Google Maps API
type GoogleMapsValidator struct {
	client *http.Client
}

// APIEndpoint represents a Google Maps API endpoint configuration
type APIEndpoint struct {
	URL        string
	Method     string
	Parameters map[string]string
	Headers    map[string]string
	PostData   map[string]string
	VulnCheck  func(*APIResponse) bool
}

// APIResponse represents the structure to check for success/failure
type APIResponse struct {
	StatusCode   int
	Content      []byte
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// Define API endpoints for validation
var googleMapsEndpoints = []APIEndpoint{
	{
		// Static Map API
		URL:    "https://maps.googleapis.com/maps/api/staticmap",
		Method: "GET",
		Parameters: map[string]string{
			"center": "45,10",
			"zoom":   "7",
			"size":   "400x400",
		},
		Headers: map[string]string{
			"Accept": "*/*",
		},
		VulnCheck: func(resp *APIResponse) bool {
			return resp.StatusCode == 200 || bytes.Contains(resp.Content, []byte("PNG"))
		},
	},
	{
		// Street View API
		URL:    "https://maps.googleapis.com/maps/api/streetview",
		Method: "GET",
		Parameters: map[string]string{
			"size":     "400x400",
			"location": "40.720032,-73.988354",
			"fov":      "90",
			"heading":  "235",
			"pitch":    "10",
		},
		Headers: map[string]string{
			"Accept": "*/*",
		},
		VulnCheck: func(resp *APIResponse) bool {
			return resp.StatusCode == 200 || bytes.Contains(resp.Content, []byte("PNG"))
		},
	},
	{
		// Directions API
		URL:    "https://maps.googleapis.com/maps/api/directions/json",
		Method: "GET",
		Parameters: map[string]string{
			"origin":      "Disneyland",
			"destination": "Universal Studios Hollywood",
		},
		Headers: map[string]string{
			"Accept": "application/json",
		},
		VulnCheck: func(resp *APIResponse) bool {
			return resp.StatusCode == 200 && resp.ErrorMessage == ""
		},
	},
	{
		// Geolocation API
		URL:    "https://www.googleapis.com/geolocation/v1/geolocate",
		Method: "POST",
		PostData: map[string]string{
			"considerIp": "true",
		},
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		VulnCheck: func(resp *APIResponse) bool {
			return resp.StatusCode == 200 && !bytes.Contains(resp.Content, []byte("error"))
		},
	},
}

// NewGoogleMapsValidator creates a new Google Maps validator instance
func NewGoogleMapsValidator() *GoogleMapsValidator {
	return &GoogleMapsValidator{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (v *GoogleMapsValidator) GetService() string {
	return "Google Safe Browsing API Key"
}

func (v *GoogleMapsValidator) GetValidationMethod() validator.ValidationMethod {
	return validator.MethodHTTP
}

// validateEndpoint checks a single API endpoint
func (v *GoogleMapsValidator) validateEndpoint(ctx context.Context, endpoint APIEndpoint, key string) (*APIResponse, error) {
	// Build URL with parameters
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Add parameters
	q := u.Query()
	q.Set("key", key)
	for k, v := range endpoint.Parameters {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	var body io.Reader
	if endpoint.Method == "POST" && len(endpoint.PostData) > 0 {
		postData, err := json.Marshal(endpoint.PostData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal post data: %w", err)
		}
		body = bytes.NewBuffer(postData)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range endpoint.Headers {
		req.Header.Set(k, v)
	}

	// Perform request
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	apiResp := &APIResponse{
		StatusCode: resp.StatusCode,
		Content:    content,
	}

	// Try to decode JSON if present
	json.Unmarshal(content, apiResp) // Ignore error as we might have non-JSON responses

	return apiResp, nil
}

// Validate performs the validation across all endpoints
func (v *GoogleMapsValidator) Validate(ctx context.Context, key string) (*validator.ValidationResult, error) {
	result := &validator.ValidationResult{
		Service:     v.GetService(),
		ValidatedAt: time.Now(),
		Details:     make(map[string]interface{}),
	}

	// Track vulnerable endpoints
	vulnerableAPIs := make([]string, 0)

	// Check each endpoint
	for _, endpoint := range googleMapsEndpoints {
		resp, err := v.validateEndpoint(ctx, endpoint, key)
		if err != nil {
			result.Details[endpoint.URL] = fmt.Sprintf("Error: %v", err)
			continue
		}

		// Check if endpoint is vulnerable using its specific check
		if endpoint.VulnCheck(resp) {
			result.Valid = true // If any endpoint is vulnerable, the key is considered valid
			vulnerableAPIs = append(vulnerableAPIs, endpoint.URL)
		}

		// Store response details
		result.Details[endpoint.URL] = map[string]interface{}{
			"status_code": resp.StatusCode,
			"vulnerable":  endpoint.VulnCheck(resp),
		}
	}

	// Set permissions based on vulnerable APIs
	result.Permissions = vulnerableAPIs

	// Set risk level based on number of vulnerable endpoints
	result.RiskLevel = v.assessRiskLevel(vulnerableAPIs)

	if !result.Valid {
		result.Error = validator.ErrInvalidKey
		result.ErrorStr = "API key not vulnerable for any endpoints"
	}

	return result, nil
}

// assessRiskLevel determines the risk level based on number of vulnerable endpoints
func (v *GoogleMapsValidator) assessRiskLevel(vulnerableAPIs []string) validator.RiskLevel {
	switch len(vulnerableAPIs) {
	case 0:
		return validator.RiskLevelLow
	case 1, 2:
		return validator.RiskLevelMedium
	default:
		return validator.RiskLevelHigh
	}
}
