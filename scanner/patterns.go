// Package scanner provides high-performance secret detection patterns
// for Lattice-Shield. Each pattern is compiled once at startup for
// maximum throughput.
package scanner

import "regexp"

// Severity levels used across all rules.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Pattern defines a single secret-detection rule.
type Pattern struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Regex       *regexp.Regexp
	Tags        []string
}

// AllPatterns is the master list of detection rules.
// Regexes are compiled once at init time — never inside hot paths.
var AllPatterns = []Pattern{

	// ── AWS ──────────────────────────────────────────────────────────────────
	{
		ID:          "AWS-001",
		Name:        "AWS Access Key ID",
		Description: "Amazon Web Services Access Key ID detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		Tags:        []string{"aws", "cloud", "credentials"},
	},
	{
		ID:          "AWS-002",
		Name:        "AWS Secret Access Key",
		Description: "Amazon Web Services Secret Access Key detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`(?i)aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key[\s'"=:]+([A-Za-z0-9/+=]{40})`),
		Tags:        []string{"aws", "cloud", "credentials"},
	},
	{
		ID:          "AWS-003",
		Name:        "AWS Session Token",
		Description: "Amazon Web Services temporary session token detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)aws[_\-.]?session[_\-.]?token[\s'"=:]+([A-Za-z0-9/+=]{100,})`),
		Tags:        []string{"aws", "cloud", "session"},
	},

	// ── Stripe ───────────────────────────────────────────────────────────────
	{
		ID:          "STRIPE-001",
		Name:        "Stripe Live Secret Key",
		Description: "Stripe PRODUCTION secret key — immediate rotation required",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		Tags:        []string{"stripe", "payment", "credentials"},
	},
	{
		ID:          "STRIPE-002",
		Name:        "Stripe Test Secret Key",
		Description: "Stripe test secret key detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
		Tags:        []string{"stripe", "payment", "credentials"},
	},
	{
		ID:          "STRIPE-003",
		Name:        "Stripe Publishable Key",
		Description: "Stripe publishable key detected",
		Severity:    SeverityMedium,
		Regex:       regexp.MustCompile(`pk_(live|test)_[0-9a-zA-Z]{24,}`),
		Tags:        []string{"stripe", "payment"},
	},
	{
		ID:          "STRIPE-004",
		Name:        "Stripe Restricted Key",
		Description: "Stripe restricted key detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`rk_(live|test)_[0-9a-zA-Z]{24,}`),
		Tags:        []string{"stripe", "payment", "credentials"},
	},

	// ── Slack ─────────────────────────────────────────────────────────────────
	{
		ID:          "SLACK-001",
		Name:        "Slack Incoming Webhook URL",
		Description: "Slack Incoming Webhook URL detected — exposes a channel endpoint",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}`),
		Tags:        []string{"slack", "webhook"},
	},
	{
		ID:          "SLACK-002",
		Name:        "Slack Bot Token",
		Description: "Slack Bot User OAuth Token detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{23,25}`),
		Tags:        []string{"slack", "oauth", "credentials"},
	},
	{
		ID:          "SLACK-003",
		Name:        "Slack User Token",
		Description: "Slack User OAuth Token detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}`),
		Tags:        []string{"slack", "oauth", "credentials"},
	},
	{
		ID:          "SLACK-004",
		Name:        "Slack App-Level Token",
		Description: "Slack App-Level Token (socket mode) detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`xapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-zA-Z0-9]{80,}`),
		Tags:        []string{"slack", "credentials"},
	},

	// ── Private Cryptographic Keys ────────────────────────────────────────────
	{
		ID:          "KEY-001",
		Name:        "RSA Private Key",
		Description: "RSA private key (PKCS#1) block header detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
		Tags:        []string{"crypto", "private-key", "rsa"},
	},
	{
		ID:          "KEY-002",
		Name:        "EC Private Key",
		Description: "Elliptic Curve private key block header detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
		Tags:        []string{"crypto", "private-key", "ec"},
	},
	{
		ID:          "KEY-003",
		Name:        "OpenSSH Private Key",
		Description: "OpenSSH private key block header detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
		Tags:        []string{"crypto", "private-key", "ssh"},
	},
	{
		ID:          "KEY-004",
		Name:        "PGP/GPG Private Key",
		Description: "PGP/GPG private key block detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		Tags:        []string{"crypto", "private-key", "pgp"},
	},
	{
		ID:          "KEY-005",
		Name:        "DSA Private Key",
		Description: "DSA private key block header detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
		Tags:        []string{"crypto", "private-key", "dsa"},
	},
	{
		ID:          "KEY-006",
		Name:        "PKCS#8 Private Key",
		Description: "Generic PKCS#8 private key block header detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
		Tags:        []string{"crypto", "private-key", "pkcs8"},
	},

	// ── GitHub ────────────────────────────────────────────────────────────────
	{
		ID:          "GH-001",
		Name:        "GitHub Personal Access Token (Classic)",
		Description: "GitHub classic PAT — 40-character prefix ghp_",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
		Tags:        []string{"github", "pat", "credentials"},
	},
	{
		ID:          "GH-002",
		Name:        "GitHub Fine-Grained Token",
		Description: "GitHub fine-grained personal access token detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`),
		Tags:        []string{"github", "pat", "credentials"},
	},
	{
		ID:          "GH-003",
		Name:        "GitHub OAuth Token",
		Description: "GitHub OAuth access token detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`gho_[a-zA-Z0-9]{36}`),
		Tags:        []string{"github", "oauth", "credentials"},
	},
	{
		ID:          "GH-004",
		Name:        "GitHub App Installation Token",
		Description: "GitHub App installation access token detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),
		Tags:        []string{"github", "app", "credentials"},
	},

	// ── Google / GCP ─────────────────────────────────────────────────────────
	{
		ID:          "GCP-001",
		Name:        "Google API Key",
		Description: "Google Cloud / Maps API Key detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Tags:        []string{"google", "gcp", "api-key"},
	},
	{
		ID:          "GCP-002",
		Name:        "Google OAuth Client Secret",
		Description: "Google OAuth 2.0 Client Secret detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`GOCSPX-[a-zA-Z0-9\-_]{28}`),
		Tags:        []string{"google", "oauth", "credentials"},
	},
	{
		ID:          "GCP-003",
		Name:        "Google Service Account JSON",
		Description: "Google Cloud Service Account key file signature detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		Tags:        []string{"google", "gcp", "service-account"},
	},

	// ── Azure ─────────────────────────────────────────────────────────────────
	{
		ID:          "AZ-001",
		Name:        "Azure Storage Connection String",
		Description: "Azure Storage Account connection string with key detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};`),
		Tags:        []string{"azure", "storage", "credentials"},
	},
	{
		ID:          "AZ-002",
		Name:        "Azure SAS Token",
		Description: "Azure Shared Access Signature token detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)sig=[A-Za-z0-9%+/]+=&se=[0-9T%\-:Z]+`),
		Tags:        []string{"azure", "sas", "credentials"},
	},

	// ── Databases ─────────────────────────────────────────────────────────────
	{
		ID:          "DB-001",
		Name:        "PostgreSQL Connection String",
		Description: "PostgreSQL connection string with embedded credentials detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`postgres(?:ql)?://[^:@\s]+:[^@\s]+@[^\s"']+`),
		Tags:        []string{"database", "postgres", "credentials"},
	},
	{
		ID:          "DB-002",
		Name:        "MySQL Connection String",
		Description: "MySQL/MariaDB connection string with embedded credentials detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`mysql://[^:@\s]+:[^@\s]+@[^\s"']+`),
		Tags:        []string{"database", "mysql", "credentials"},
	},
	{
		ID:          "DB-003",
		Name:        "MongoDB Connection String",
		Description: "MongoDB Atlas connection string with embedded credentials detected",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@[^\s"']+`),
		Tags:        []string{"database", "mongodb", "credentials"},
	},
	{
		ID:          "DB-004",
		Name:        "Redis Connection String",
		Description: "Redis connection string with password detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`redis://:[^@\s]+@[^\s"']+`),
		Tags:        []string{"database", "redis", "credentials"},
	},

	// ── JWT ───────────────────────────────────────────────────────────────────
	{
		ID:          "JWT-001",
		Name:        "JSON Web Token",
		Description: "JWT token detected — may contain sensitive claims or signing secrets",
		Severity:    SeverityMedium,
		Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
		Tags:        []string{"jwt", "auth", "token"},
	},

	// ── Hardcoded Credentials ─────────────────────────────────────────────────
	{
		ID:          "CRED-001",
		Name:        "Hardcoded Password",
		Description: "Hardcoded password value in source code detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["'][^"']{8,}["']`),
		Tags:        []string{"credentials", "password"},
	},
	{
		ID:          "CRED-002",
		Name:        "Hardcoded API Key",
		Description: "Hardcoded API key assignment detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["'][A-Za-z0-9\-_]{16,}["']`),
		Tags:        []string{"credentials", "api-key"},
	},
	{
		ID:          "CRED-003",
		Name:        "Hardcoded Secret or Token",
		Description: "Hardcoded secret / auth token assignment detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)(?:secret[_\-]?(?:key)?|auth[_\-]?token|access[_\-]?token)\s*[=:]\s*["'][A-Za-z0-9\-_/+=]{16,}["']`),
		Tags:        []string{"credentials", "secret"},
	},
	{
		ID:          "CRED-004",
		Name:        "Basic Auth Credentials in URL",
		Description: "HTTP Basic Auth username:password embedded in URL",
		Severity:    SeverityCritical,
		Regex:       regexp.MustCompile(`https?://[^:@\s"']+:[^@\s"']+@[^\s"']+`),
		Tags:        []string{"credentials", "http", "basic-auth"},
	},

	// ── Communication APIs ────────────────────────────────────────────────────
	{
		ID:          "MSG-001",
		Name:        "Twilio API Key",
		Description: "Twilio API Key (SK prefix) detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Tags:        []string{"twilio", "credentials"},
	},
	{
		ID:          "MSG-002",
		Name:        "SendGrid API Key",
		Description: "SendGrid API key detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`),
		Tags:        []string{"sendgrid", "email", "credentials"},
	},
	{
		ID:          "MSG-003",
		Name:        "Mailgun API Key",
		Description: "Mailgun API key detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Tags:        []string{"mailgun", "email", "credentials"},
	},

	// ── DevOps / Registry Tokens ──────────────────────────────────────────────
	{
		ID:          "DEV-001",
		Name:        "NPM Authentication Token",
		Description: "NPM registry authentication token detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Tags:        []string{"npm", "registry", "credentials"},
	},
	{
		ID:          "DEV-002",
		Name:        "PyPI Upload Token",
		Description: "Python Package Index (PyPI) upload token detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`pypi-[A-Za-z0-9\-_]{40,}`),
		Tags:        []string{"pypi", "python", "credentials"},
	},
	{
		ID:          "DEV-003",
		Name:        "Heroku API Key",
		Description: "Heroku API key UUID pattern detected",
		Severity:    SeverityHigh,
		Regex:       regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key[\s'"=:]+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`),
		Tags:        []string{"heroku", "credentials"},
	},

	// ── Internal / Proprietary Network ───────────────────────────────────────
	{
		ID:          "INT-001",
		Name:        "Hardcoded Private IP Address",
		Description: "RFC-1918 private IP address hardcoded in source — exposes internal topology",
		Severity:    SeverityMedium,
		Regex:       regexp.MustCompile(`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`),
		Tags:        []string{"network", "internal"},
	},
	{
		ID:          "INT-002",
		Name:        "Internal Domain Suffix",
		Description: "Internal/corporate domain suffix (.internal, .corp, .local) detected",
		Severity:    SeverityLow,
		Regex:       regexp.MustCompile(`[a-zA-Z0-9\-]+\.(?:internal|corp|local|intranet|lan)\b`),
		Tags:        []string{"network", "internal", "domain"},
	},
}
