package input

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// PatternConfig and ServicePattern types moved from detector package
type ServicePattern struct {
	Patterns []string `json:"patterns"`
	Prefixes []string `json:"prefixes"`
	Length   []int    `json:"length"`
}

type PatternConfig map[string]ServicePattern

// ValidatePatternFile checks if the pattern file exists and contains valid configuration
func ValidatePatternFile(configPath string) error {
	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Check if file is valid JSON
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON format in config file")
	}

	var patterns PatternConfig
	if err := json.Unmarshal(data, &patterns); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return validatePatternConfig(patterns)
}

// validatePatternConfig checks if the pattern configuration is valid
func validatePatternConfig(config PatternConfig) error {
	if len(config) == 0 {
		return fmt.Errorf("config must contain at least one service")
	}

	for service, pattern := range config {
		if service == "" {
			return fmt.Errorf("empty service name not allowed")
		}
		if err := validateServicePattern(pattern); err != nil {
			return fmt.Errorf("invalid pattern for service '%s': %w", service, err)
		}
	}

	return nil
}

// validateServicePattern checks if a service pattern is valid
func validateServicePattern(sp ServicePattern) error {
	if len(sp.Patterns) == 0 {
		return fmt.Errorf("at least one pattern is required")
	}

	// Validate each regex pattern
	for i, pattern := range sp.Patterns {
		if pattern == "" {
			return fmt.Errorf("empty pattern at index %d", i)
		}
		if _, err := regexp.Compile("^" + pattern + "$"); err != nil {
			return fmt.Errorf("invalid regex pattern at index %d: %s", i, err)
		}
	}

	// Validate prefixes (optional but if present should not be empty)
	for i, prefix := range sp.Prefixes {
		if prefix == "" {
			return fmt.Errorf("empty prefix at index %d", i)
		}
	}

	// Validate lengths (optional but if present should be positive)
	for i, length := range sp.Length {
		if length <= 0 {
			return fmt.Errorf("invalid length at index %d: must be positive", i)
		}
	}

	return nil
}
