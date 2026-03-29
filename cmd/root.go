// Package cmd provides the Cobra-based CLI for Lattice-Shield.
package cmd

import (
	"github.com/spf13/cobra"
)

const banner = `
  ┌──────────────────────────────────────────────────────────┐
  │   LATTICE-SHIELD  v1.0.0  —  The AI-Code Sentinel        │
  │                                                          │
  │   "Protecting Company Secrets from AI Training Data"     │
  └──────────────────────────────────────────────────────────┘`

var rootCmd = &cobra.Command{
	Use:     "lattice-shield",
	Short:   "The AI-Code Sentinel — Stop IP leakage to public LLMs",
	Long:    banner + "\n\n  The firewall between your proprietary algorithms and the public cloud AI.",
	Version: "1.0.0",
}

// Execute runs the root command and returns any error.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Show matched values (masked)")
	rootCmd.PersistentFlags().BoolP("json", "j", false, "Output results as JSON")
	rootCmd.PersistentFlags().String("proxy", "http://localhost:8080", "Lattice-Proxy address for PII scrubbing")
}
