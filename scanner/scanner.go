// Package scanner implements the core secret-detection engine for Lattice-Shield.
package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Finding represents a single detected secret or sensitive pattern.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Line        int      `json:"line"`
	Column      int      `json:"column"`
	Source      string   `json:"source"`
	MaskedValue string   `json:"masked_value"`
	Tags        []string `json:"tags"`
}

// Scanner is the main secret-detection engine.
type Scanner struct {
	patterns []Pattern
}

// New returns a Scanner pre-loaded with all default patterns.
func New() *Scanner {
	return &Scanner{patterns: AllPatterns}
}

// WithPatterns returns a Scanner using only the given patterns.
func WithPatterns(patterns []Pattern) *Scanner {
	return &Scanner{patterns: patterns}
}

// Scan inspects code line-by-line against all loaded patterns.
// source is a human-readable label (file path or "<stdin>").
func (s *Scanner) Scan(code, source string) []Finding {
	lines := strings.Split(code, "\n")
	var findings []Finding

	for lineIdx, line := range lines {
		for _, p := range s.patterns {
			loc := p.Regex.FindStringIndex(line)
			if loc == nil {
				continue
			}
			match := line[loc[0]:loc[1]]
			findings = append(findings, Finding{
				RuleID:      p.ID,
				RuleName:    p.Name,
				Description: p.Description,
				Severity:    p.Severity,
				Line:        lineIdx + 1,
				Column:      loc[0] + 1,
				Source:      source,
				MaskedValue: maskSecret(match),
				Tags:        p.Tags,
			})
		}
	}

	return findings
}

// maskSecret replaces the middle of a secret value with asterisks.
func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	prefix := s[:4]
	suffix := s[len(s)-4:]
	return prefix + strings.Repeat("*", len(s)-8) + suffix
}

// FilterBySeverity returns only findings with the given severity level.
func FilterBySeverity(findings []Finding, severity string) []Finding {
	var out []Finding
	upper := strings.ToUpper(severity)
	for _, f := range findings {
		if f.Severity == upper {
			out = append(out, f)
		}
	}
	return out
}

// CountBySeverity counts findings matching the given severity level.
func CountBySeverity(findings []Finding, severity string) int {
	count := 0
	for _, f := range findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}

// PrintJSON serialises findings to indented JSON on stdout.
func PrintJSON(findings []Finding) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		fmt.Println("[]")
		return
	}
	fmt.Println(string(data))
}
