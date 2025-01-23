package input

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Parser handles different input methods for API keys
type Parser struct {
	verbose bool
}

// NewParser creates a new Parser instance
func NewParser(verbose bool) *Parser {
	return &Parser{
		verbose: verbose,
	}
}

// FromStdin reads and deduplicates keys from standard input
func (p *Parser) FromStdin() ([]string, error) {
	if p.verbose {
		fmt.Println("Reading keys from stdin...")
	}

	seen := make(map[string]bool)
	var keys []string
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		key := strings.TrimSpace(scanner.Text())
		if key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading from stdin: %w", err)
	}

	if p.verbose {
		fmt.Printf("Found %d unique keys from stdin\n", len(keys))
	}

	return keys, nil
}

// FromFile reads and deduplicates keys from a file
func (p *Parser) FromFile(filename string) ([]string, error) {
	if p.verbose {
		fmt.Printf("Reading keys from file: %s\n", filename)
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	seen := make(map[string]bool)
	var keys []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		key := strings.TrimSpace(scanner.Text())
		if key != "" && !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading from file: %w", err)
	}

	if p.verbose {
		fmt.Printf("Found %d unique keys from file\n", len(keys))
	}

	return keys, nil
}

// FromSingle creates a single-element slice from a key
func (p *Parser) FromSingle(key string) []string {
	if p.verbose {
		fmt.Println("Processing single key")
	}
	return []string{strings.TrimSpace(key)}
}

// IsStdinPipe checks if input is being piped to stdin
func IsStdinPipe() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}
