package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/lattice-suite/lattice-shield/scanner"
	"github.com/spf13/cobra"
)

var (
	severityFilter string
	exitOnDetect   bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan a file or stdin for secrets and sensitive patterns",
	Long: `Scan source code for secrets, API keys, and sensitive patterns.
If no file is provided, reads from stdin.

Examples:
  lattice-shield scan main.go
  lattice-shield scan --severity CRITICAL config.env
  lattice-shield scan --json --exit-on-detect src/
  cat internal.go | lattice-shield scan`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVarP(&severityFilter, "severity", "s", "", "Filter by severity: CRITICAL | HIGH | MEDIUM | LOW")
	scanCmd.Flags().BoolVarP(&exitOnDetect, "exit-on-detect", "e", false, "Exit with code 1 when secrets are found (CI/CD mode)")
}

func runScan(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	type fileEntry struct {
		source string
		data   []byte
	}

	var inputs []fileEntry

	if len(args) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		inputs = append(inputs, fileEntry{"<stdin>", data})
	} else {
		for _, arg := range args {
			data, err := os.ReadFile(arg)
			if err != nil {
				return fmt.Errorf("failed to read %q: %w", arg, err)
			}
			inputs = append(inputs, fileEntry{arg, data})
		}
	}

	s := scanner.New()
	var allFindings []scanner.Finding

	for _, entry := range inputs {
		findings := s.Scan(string(entry.data), entry.source)
		if severityFilter != "" {
			findings = scanner.FilterBySeverity(findings, strings.ToUpper(severityFilter))
		}
		allFindings = append(allFindings, findings...)
	}

	if jsonOutput {
		scanner.PrintJSON(allFindings)
	} else {
		printScanResults(allFindings, verbose)
	}

	if exitOnDetect && len(allFindings) > 0 {
		os.Exit(1)
	}

	return nil
}

func printScanResults(findings []scanner.Finding, verbose bool) {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)

	fmt.Println()
	bold.Println("  Lattice-Shield — Scan Report")
	fmt.Println()

	if len(findings) == 0 {
		green.Println("  ✓ No secrets detected. Code is safe to share with LLMs.")
		fmt.Println()
		return
	}

	red.Printf("  ✗ %d secret(s) detected\n\n", len(findings))

	for i, f := range findings {
		fmt.Printf("  [%02d] ", i+1)
		switch f.Severity {
		case scanner.SeverityCritical:
			red.Printf("%-10s", f.Severity)
		case scanner.SeverityHigh:
			red.Printf("%-10s", f.Severity)
		case scanner.SeverityMedium:
			yellow.Printf("%-10s", f.Severity)
		default:
			cyan.Printf("%-10s", f.Severity)
		}
		bold.Printf(" %s\n", f.RuleName)
		fmt.Printf("        %s:%d — %s\n", f.Source, f.Line, f.Description)
		if verbose {
			fmt.Printf("        Match:  %s\n", f.MaskedValue)
		}
		fmt.Println()
	}

	fmt.Println("  ─────────────────────────────────────────────────────")
	critical := scanner.CountBySeverity(findings, scanner.SeverityCritical)
	high := scanner.CountBySeverity(findings, scanner.SeverityHigh)
	medium := scanner.CountBySeverity(findings, scanner.SeverityMedium)
	low := scanner.CountBySeverity(findings, scanner.SeverityLow)
	red.Printf("  CRITICAL: %-4d HIGH: %-4d", critical, high)
	yellow.Printf(" MEDIUM: %-4d", medium)
	cyan.Printf(" LOW: %d\n\n", low)
}
