package detector

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// Add this at the top with other type declarations
var verbose bool

// Add this function to set verbose mode
func SetVerbose(v bool) {
	verbose = v
}

// Pattern represents the new pattern structure
type Pattern struct {
	Name  []string `json:"Name"`
	Regex string   `json:"Regex"`
}

// KeyDetector handles API key pattern detection
type KeyDetector struct {
	patterns []Pattern
	compiled map[string]*regexp.Regexp
	verbose  bool
}

// Add new type for confidence calculation
type matchConfidence struct {
	service    string
	confidence float64
	reason     string
}

// DetectServiceDetailed returns detailed information about the key detection
type DetectionResult struct {
	Service    string   `json:"service"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
}

// ValidatePattern checks if a pattern configuration is valid
func ValidatePattern(pattern Pattern) error {
	if len(pattern.Name) == 0 {
		return fmt.Errorf("pattern must have at least one name")
	}

	if pattern.Regex == "" {
		return fmt.Errorf("pattern must have a regex")
	}

	// Try compiling the regex
	if _, err := regexp.Compile(pattern.Regex); err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	return nil
}

// NewKeyDetector creates a new KeyDetector instance from a byte slice
func NewKeyDetector(configData []byte) (*KeyDetector, error) {
	var patterns []Pattern
	if err := json.Unmarshal(configData, &patterns); err != nil {
		return nil, fmt.Errorf("failed to parse config data: %w", err)
	}

	// Compile all regex patterns
	compiled := make(map[string]*regexp.Regexp)
	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern for %s: %w", pattern.Name[0], err)
		}
		for _, name := range pattern.Name {
			compiled[name] = re
		}
	}

	return &KeyDetector{
		patterns: patterns,
		compiled: compiled,
	}, nil
}

// DetectService identifies the service based on the API key pattern
func (d *KeyDetector) DetectService(key string) string {
	for _, pattern := range d.patterns {
		re := d.compiled[pattern.Name[0]]
		if re.MatchString(key) {
			if d.verbose {
				fmt.Printf("Detected service: %s\n", pattern.Name[0])
			}
			return pattern.Name[0]
		}
	}
	return ""
}

// SetVerbose enables or disables verbose output
func (d *KeyDetector) SetVerbose(verbose bool) {
	d.verbose = verbose
}

// DetectServiceDetailed returns detailed information about the key detection
func (d *KeyDetector) DetectServiceDetailed(key string) DetectionResult {
	service := d.DetectService(key)
	return DetectionResult{
		Service:    service,
		Confidence: 1.0, // Assuming full confidence for detected service
		Reasons:    []string{fmt.Sprintf("Detected service: %s", service)},
	}
}

func loadPatterns(configPath string) ([]Pattern, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var patterns []Pattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return patterns, nil
}
