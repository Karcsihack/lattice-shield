package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/lattice-suite/lattice-shield/scanner"
	"github.com/spf13/cobra"
)

var blockOnHighOrAbove bool

var checkCmd = &cobra.Command{
	Use:   "check [files...]",
	Short: "Pre-commit security check: scan staged files and block on secrets",
	Long: `Run a full security scan suitable for Git pre-commit hooks.
Exits with code 1 if CRITICAL or HIGH secrets are detected, blocking the commit.

Install automatically:
  lattice-shield install-hook

Or wire manually in .git/hooks/pre-commit:
  lattice-shield check $(git diff --cached --name-only)`,
	RunE: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().BoolVar(&blockOnHighOrAbove, "block-high", true, "Block commit on HIGH or CRITICAL findings")
}

func runCheck(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow)

	bold.Println("\n  ╔══════════════════════════════════════════╗")
	bold.Println("  ║   Lattice-Shield — Pre-Commit Check      ║")
	bold.Println("  ╚══════════════════════════════════════════╝")

	if len(args) == 0 {
		yellow.Println("  No staged files provided — nothing to check.")
		return nil
	}

	s := scanner.New()
	totalFindings := 0
	criticalOrHigh := 0
	scannedFiles := 0

	for _, file := range args {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: cannot read %s: %v\n", file, err)
			continue
		}
		scannedFiles++

		findings := s.Scan(string(data), file)
		if len(findings) > 0 {
			red.Printf("  ✗ %s — %d finding(s)\n", file, len(findings))
			for _, f := range findings {
				fmt.Printf("    [%s] Line %d: %s\n", f.Severity, f.Line, f.RuleName)
			}
			totalFindings += len(findings)
			criticalOrHigh += scanner.CountBySeverity(findings, scanner.SeverityCritical) +
				scanner.CountBySeverity(findings, scanner.SeverityHigh)
		} else {
			green.Printf("  ✓ %s\n", file)
		}
	}

	fmt.Println()
	fmt.Printf("  Scanned %d file(s). ", scannedFiles)

	if totalFindings == 0 {
		green.Println("All clear — commit allowed.")
		return nil
	}

	red.Printf("BLOCKED — %d secret(s) detected.\n", totalFindings)
	fmt.Println("  Run 'lattice-shield anonymize <file>' to sanitize before committing.")

	if blockOnHighOrAbove && criticalOrHigh > 0 {
		os.Exit(1)
	}

	return nil
}
