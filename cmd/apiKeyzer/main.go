package main

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"os"
	"strings"

	"github.com/Xplo8E/APIKeyzer/internal/detector"
	"github.com/Xplo8E/APIKeyzer/internal/input"
	"github.com/Xplo8E/APIKeyzer/internal/validator"
	"github.com/Xplo8E/APIKeyzer/internal/validator/services"
	"github.com/spf13/cobra"
)

// Embed the default patterns.json configuration file

//go:embed config/patterns.json
var embeddedConfig embed.FS

var (
	inputFile  string
	apiKey     string
	verbose    bool
	configFile string
	rootCmd    *cobra.Command
)

var (
	Red    = Color("\033[1;31m%s\033[0m")
	Green  = Color("\033[1;32m%s\033[0m")
	Yellow = Color("\033[1;33m%s\033[0m")
	Blue   = Color("\033[1;34m%s\033[0m")
	Cyan   = Color("\033[1;36m%s\033[0m")
)

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

var version = "v1.0"
var banner = fmt.Sprintf(`
  ___  ______ _____ _   __                        
 / _ \ | ___ \_   _| | / /                        
/ /_\ \| |_/ / | | | |/ /  ___ _   _ _______ _ __ 
|  _  ||  __/  | | |    \ / _ \ | | |_  / _ \ '__|
| | | || |    _| |_| |\  \  __/ |_| |/ /  __/ |   
\_| |_/\_|    \___/\_| \_/\___|\__, /___\___|_|   
                                __/ |             
                               |___/  %s
                                      @Xplo8E`, version)

func show_banner() {
	fmt.Println(Blue(banner))
}

func init() {
	show_banner()
	rootCmd = &cobra.Command{
		Use:   "apiKeyzer",
		Short: "APIKeyzer - API Key Detection and Validation Tool",
		Long: `
Examples:
  apiKeyzer --key "YOUR-API-KEY"
  apiKeyzer --list keys.txt
  cat keys.txt | apiKeyzer
  apiKeyzer --key "YOUR-API-KEY" --config custom-patterns.json`,
		Run: runValidation,
	}

	// Add flags
	rootCmd.PersistentFlags().StringVarP(&inputFile, "list", "l", "", "File containing API keys (one per line)")
	rootCmd.PersistentFlags().StringVarP(&apiKey, "key", "k", "", "Single API key to validate")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Path to patterns configuration file (default will be used if not provided)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func processStdin() ([]string, error) {
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
	return keys, scanner.Err()
}

func processFile(filename string) ([]string, error) {
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
	return keys, scanner.Err()
}

func initValidators() *validator.ValidationManager {
	vm := validator.NewValidationManager()

	// Register Google Maps validator
	vm.RegisterValidator(services.NewGoogleMapsValidator())

	return vm
}

func runValidation(cmd *cobra.Command, args []string) {

	var configContent []byte
	var err error

	if configFile != "" {
		configContent, err = os.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file '%s': %v\n", configFile, err)
			os.Exit(1)
		}
	} else {
		configContent, err = embeddedConfig.ReadFile("config/patterns.json")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading embedded config: %v\n", err)
			os.Exit(1)
		}
	}

	// Initialize validators
	validationManager := initValidators()

	// Initialize input parser
	parser := input.NewParser(verbose)

	// Initialize detector
	detector, err := detector.NewKeyDetector(configContent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config file '%s': %v\n", configFile, err)
		os.Exit(1)
	}

	detector.SetVerbose(verbose)

	var keys []string

	// Handle different input methods
	switch {
	case input.IsStdinPipe():
		keys, err = parser.FromStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case inputFile != "" && apiKey != "":
		fmt.Println("Error: Cannot use both --list and --key simultaneously")
		os.Exit(1)

	case inputFile != "":
		keys, err = parser.FromFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case apiKey != "":
		keys = parser.FromSingle(apiKey)

	default:
		if !input.IsStdinPipe() {
			// fmt.Println("Error: Either --list or --key must be provided, or pipe data through stdin")
			cmd.Help()
			// os.Exit(1)
		}
	}

	// Process the keys
	for _, key := range keys {
		// Detect service first
		service := detector.DetectService(key)
		if service == "" {
			fmt.Printf("Unknown service for key: %s\n", key)
			continue
		}

		// Validate the key
		result, err := validationManager.ValidateKey(context.Background(), service, key)
		if err != nil {
			fmt.Printf("Error validating key %s: %v\n", key, Yellow(err))
			continue
		}

		// Print results
		printValidationResult(result, key)
	}
}

func printValidationResult(result *validator.ValidationResult, key string) {
	if result.Valid {
		// fmt.Printf("\n[+] Valid key for %s!\n", result.Service)
		fmt.Println(Red("[+] Vulnerable API Key: "), key)
		// fmt.Printf("[-] Vulnerable APIs:\n")
		// for _, perm := range result.Permissions {
		// 	fmt.Printf("    - %s\n", perm)
		// }
		// fmt.Printf("[-] Risk Level: %s\n", result.RiskLevel)
	} else {
		fmt.Printf("\n[-] Invalid key for %s: %s\n", result.Service, result.ErrorStr)
	}

	if verbose {
		fmt.Printf("\nDetails:\n")
		for endpoint, details := range result.Details {
			fmt.Printf("  %s: %v\n", endpoint, details)
		}
	}
}
