// Lattice-Shield — The AI-Code Sentinel
// Protects your intellectual property from LLM leakage.
//
// Part of the Lattice Suite: Enterprise AI Governance Platform.
// Copyright (c) 2026 Lattice Suite. All rights reserved.
package main

import (
	"fmt"
	"os"

	"github.com/lattice-suite/lattice-shield/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
