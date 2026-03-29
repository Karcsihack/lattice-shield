// Package anonymizer replaces proprietary identifiers with opaque placeholders
// before source code is shared with any LLM.
//
// For Go source files it uses the standard go/ast package for accurate,
// syntax-aware renaming. For all other languages it falls back to
// regex-based heuristics.
package anonymizer

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
)

// Anonymizer holds the replacement map built during a single Anonymize call.
type Anonymizer struct {
	replacements map[string]string
	counter      int
}

// New returns a fresh Anonymizer.
func New() *Anonymizer {
	return &Anonymizer{replacements: make(map[string]string)}
}

// sensitivePatterns identifies function / variable names that look proprietary.
// Patterns are conservative — only clear business-domain terminology is matched.
var sensitivePatterns = []*regexp.Regexp{
	// snake_case: verb + internal-domain noun
	regexp.MustCompile(`(?i)\b(calc|compute|process|score|assess|evaluate|apply|generate|build)(_(internal|proprietary|private|risk|fraud|credit|pricing|margin|profit|commission|fee|algo|model|engine|scorer|pipeline))\w*\b`),
	// snake_case: internal-domain modifier + noun
	regexp.MustCompile(`(?i)\b(internal|proprietary|private|core|secret|hidden)(_(calc|compute|process|score|risk|fraud|logic|handler|service|manager|engine|worker|pipeline))\w*\b`),
	// CamelCase: verb + InternalDomain
	regexp.MustCompile(`\b(calc|Calc|compute|Compute|process|Process|score|Score|assess|Assess|evaluate|Evaluate|apply|Apply|generate|Generate)(Internal|Proprietary|Private|Risk|Fraud|Credit|Pricing|Margin|Profit|Commission|Fee|Algo|Algorithm|Model|Engine|Scorer|Pipeline)\w*\b`),
	// CamelCase: InternalDomain + noun
	regexp.MustCompile(`\b(Internal|Proprietary|Private|Core|Secret|Hidden)(Calc|Compute|Process|Score|Risk|Fraud|Logic|Handler|Service|Manager|Engine|Worker|Pipeline)\w*\b`),
}

// Anonymize rewrites code by replacing sensitive identifiers with placeholders.
// lang should be the value returned by DetectLanguage.
// Returns (anonymized code, replacement map, error).
func (a *Anonymizer) Anonymize(code, lang string) (string, map[string]string, error) {
	if lang == "go" {
		return a.anonymizeGo(code)
	}
	return a.anonymizeGeneric(code)
}

// anonymizeGo uses the Go AST for precise, syntax-aware renaming.
func (a *Anonymizer) anonymizeGo(code string) (string, map[string]string, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", code, parser.ParseComments)
	if err != nil {
		// Fallback: the file may be a snippet — use generic heuristics.
		return a.anonymizeGeneric(code)
	}

	// First pass: collect every sensitive function name defined in the file.
	sensitiveNames := make(map[string]bool)
	ast.Inspect(node, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name != nil && isSensitiveName(fn.Name.Name) {
			sensitiveNames[fn.Name.Name] = true
			a.getOrCreate(fn.Name.Name)
		}
		return true
	})

	if len(sensitiveNames) == 0 {
		return code, a.replacements, nil
	}

	// Second pass: rename all occurrences (definitions + call sites).
	ast.Inspect(node, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if ok && sensitiveNames[ident.Name] {
			ident.Name = a.replacements[ident.Name]
		}
		return true
	})

	var buf strings.Builder
	if err := format.Node(&buf, fset, node); err != nil {
		return code, a.replacements, fmt.Errorf("failed to reformat anonymized Go code: %w", err)
	}

	return buf.String(), a.replacements, nil
}

// anonymizeGeneric uses regex substitution for non-Go languages.
func (a *Anonymizer) anonymizeGeneric(code string) (string, map[string]string, error) {
	result := code
	for _, p := range sensitivePatterns {
		result = p.ReplaceAllStringFunc(result, func(match string) string {
			return a.getOrCreate(match)
		})
	}
	return result, a.replacements, nil
}

// isSensitiveName returns true when name looks like an internal / proprietary identifier.
func isSensitiveName(name string) bool {
	if isCommonGoIdent(name) {
		return false
	}
	for _, p := range sensitivePatterns {
		if p.MatchString(name) {
			return true
		}
	}
	return false
}

// getOrCreate returns a stable opaque replacement for the given original.
// The replacement is deterministic across multiple Anonymize calls within
// the same Anonymizer instance.
func (a *Anonymizer) getOrCreate(original string) string {
	if existing, ok := a.replacements[original]; ok {
		return existing
	}
	a.counter++
	h := sha256.Sum256([]byte(original))
	placeholder := fmt.Sprintf("process_data_v%d_%x", a.counter, h[:2])
	a.replacements[original] = placeholder
	return placeholder
}

// DetectLanguage maps a file extension to a language tag.
func DetectLanguage(filename string) string {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".go":
		return "go"
	case ".py", ".pyw":
		return "python"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".rs":
		return "rust"
	case ".cs":
		return "csharp"
	case ".php":
		return "php"
	case ".kt", ".kts":
		return "kotlin"
	default:
		return "unknown"
	}
}

// isCommonGoIdent returns true for standard Go builtin and common SDK names
// that should never be anonymized.
func isCommonGoIdent(name string) bool {
	builtins := map[string]bool{
		// Builtins
		"append": true, "cap": true, "close": true, "complex": true,
		"copy": true, "delete": true, "imag": true, "len": true,
		"make": true, "new": true, "panic": true, "print": true,
		"println": true, "real": true, "recover": true,
		// Predeclared types
		"bool": true, "byte": true, "complex64": true, "complex128": true,
		"error": true, "float32": true, "float64": true, "int": true,
		"int8": true, "int16": true, "int32": true, "int64": true,
		"rune": true, "string": true, "uint": true, "uint8": true,
		"uint16": true, "uint32": true, "uint64": true, "uintptr": true,
		// Very common stdlib / framework identifiers
		"main": true, "init": true, "Context": true, "Error": true,
		"String": true, "Handler": true, "Server": true, "Client": true,
		"Request": true, "Response": true, "Writer": true, "Reader": true,
	}
	return builtins[name]
}
