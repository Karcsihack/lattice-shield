package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/lattice-suite/lattice-shield/anonymizer"
	"github.com/spf13/cobra"
)

var (
	outputFile string
	dryRun     bool
)

var anonymizeCmd = &cobra.Command{
	Use:   "anonymize [file]",
	Short: "Anonymize proprietary function names and business logic",
	Long: `Anonymize internal function names, proprietary algorithms, and
business-logic identifiers before sharing code with any LLM.

Uses AST-based analysis for Go source files and regex-based heuristics
for all other languages.

Examples:
  lattice-shield anonymize internal/risk_engine.go
  lattice-shield anonymize --dry-run src/scoring.go
  lattice-shield anonymize algo.go --output safe_algo.go
  cat proprietary.go | lattice-shield anonymize`,
	RunE: runAnonymize,
}

func init() {
	rootCmd.AddCommand(anonymizeCmd)
	anonymizeCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write anonymized code to this file (default: stdout)")
	anonymizeCmd.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "Preview replacements without modifying anything")
}

func runAnonymize(cmd *cobra.Command, args []string) error {
	bold := color.New(color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	green := color.New(color.FgGreen, color.Bold)

	var (
		input []byte
		err   error
		lang  string
	)

	if len(args) == 0 {
		input, err = io.ReadAll(os.Stdin)
		lang = "unknown"
	} else {
		input, err = os.ReadFile(args[0])
		lang = anonymizer.DetectLanguage(args[0])
	}
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	a := anonymizer.New()
	result, replacements, err := a.Anonymize(string(input), lang)
	if err != nil {
		return fmt.Errorf("anonymization failed: %w", err)
	}

	if dryRun {
		bold.Println("\n  Lattice-Shield — Anonymization Preview (dry-run)\n")
		if len(replacements) == 0 {
			green.Println("  No proprietary identifiers detected.")
		} else {
			for orig, anon := range replacements {
				yellow.Printf("  %-45s", orig)
				fmt.Printf(" → ")
				green.Printf("%s\n", anon)
			}
		}
		fmt.Printf("\n  Total replacements: %d\n\n", len(replacements))
		return nil
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(result), 0600); err != nil {
			return fmt.Errorf("failed to write %q: %w", outputFile, err)
		}
		green.Printf("  ✓ Anonymized code written to %s (%d replacements)\n", outputFile, len(replacements))
	} else {
		fmt.Print(result)
	}

	return nil
}
