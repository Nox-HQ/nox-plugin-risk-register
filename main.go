package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// --- Compiled regex patterns ---

var (
	// RISK-001: Security-related technical debt markers.
	reSecurityTODO = regexp.MustCompile(`(?i)(TODO|FIXME|HACK|XXX)\s*:?\s*.*(security|auth|crypt|password|secret|token|vulnerab|inject|xss|csrf|sanitiz|escap|privilege|permiss)`)

	// RISK-002: Deprecated API/pattern usage.
	reDeprecatedGo     = regexp.MustCompile(`(?i)(ioutil\.|x509\.ParseCRL|http\.ListenAndServeTLS\(|md5\.New\(\)|sha1\.New\(\)|des\.NewCipher)`)
	reDeprecatedPython = regexp.MustCompile(`(?i)(import\s+md5|import\s+sha\b|from\s+sha\s+import|\.has_key\(|print\s+[^(]|raw_input|execfile|reload\()`)
	reDeprecatedJS     = regexp.MustCompile(`(?i)(document\.write\(|escape\(|unescape\(|__proto__|Object\.observe|\.substr\()`)

	// RISK-003: Single point of failure patterns.
	reSingleDBConn = regexp.MustCompile(`(?i)(sql\.Open\(|connect\(|createConnection\(|MongoClient\()`)
	reNoPooling    = regexp.MustCompile(`(?i)(SetMaxOpenConns|pool|Pool|createPool|ConnectionPool|pool_size)`)
	reNoFallback   = regexp.MustCompile(`(?i)(fallback|failover|replica|secondary|backup|standby|redundan)`)
	// RISK-004: Missing error recovery mechanisms.
	reExternalCall   = regexp.MustCompile(`(?i)(http\.Get|http\.Post|http\.Do|requests\.(get|post|put|delete)|fetch\(|axios\.|grpc\.|\.Dial\(|\.Connect\()`)
	reRetryMechanism = regexp.MustCompile(`(?i)(retry|backoff|circuit.?breaker|resilience|polly|tenacity|retrying|go-retryablehttp|hashicorp/go-retryablehttp|sony/gobreaker|afex/hystrix)`)

	// RISK-005: Code complexity indicators.
	reNestedConditional = regexp.MustCompile(`^(\s+)(if\s|for\s|while\s|switch\s|case\s|select\s)`)
	reFuncStart         = regexp.MustCompile(`(?i)^(func\s|def\s|function\s|const\s+\w+\s*=\s*\(|\s*(public|private|protected)\s+(static\s+)?[\w<>\[\]]+\s+\w+\s*\()`)
)

// sourceExtensions lists file extensions to scan.
var sourceExtensions = map[string]bool{
	".go":   true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".jsx":  true,
	".tsx":  true,
	".java": true,
	".rb":   true,
	".cs":   true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

// riskContext tracks workspace-level risk indicators.
type riskContext struct {
	hasDBConnection  bool
	hasPooling       bool
	hasFallback      bool
	hasExternalCalls bool
	hasRetryMech     bool

	dbFile string
	dbLine int

	externalCallFile string
	externalCallLine int
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/risk-register", version).
		Capability("risk-register", "Identifies and categorizes technical risks in codebases").
		Tool("scan", "Scan source code for technical risks including debt, deprecated APIs, single points of failure, and complexity", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	rc := &riskContext{}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !sourceExtensions[ext] {
			return nil
		}

		scanFileForRisks(resp, rc, path, ext)
		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// Emit workspace-level findings.
	emitWorkspaceRisks(resp, rc)

	return resp.Build(), nil
}

// scanFileForRisks scans a single source file for risk indicators.
func scanFileForRisks(resp *sdk.ResponseBuilder, rc *riskContext, filePath, ext string) {
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	funcLineCount := 0
	funcStartLine := 0
	inFunc := false
	maxNesting := 0
	currentNesting := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// RISK-001: Security-related technical debt.
		checkSecurityDebt(resp, filePath, lineNum, line)

		// RISK-002: Deprecated API usage.
		checkDeprecatedAPI(resp, filePath, lineNum, line, ext)

		// Track DB connections and external calls for RISK-003 and RISK-004.
		if reSingleDBConn.MatchString(line) && !rc.hasDBConnection {
			rc.hasDBConnection = true
			rc.dbFile = filePath
			rc.dbLine = lineNum
		}
		if reNoPooling.MatchString(line) {
			rc.hasPooling = true
		}
		if reNoFallback.MatchString(line) {
			rc.hasFallback = true
		}
		if reExternalCall.MatchString(line) && !rc.hasExternalCalls {
			rc.hasExternalCalls = true
			rc.externalCallFile = filePath
			rc.externalCallLine = lineNum
		}
		if reRetryMechanism.MatchString(line) {
			rc.hasRetryMech = true
		}

		// RISK-005: Code complexity tracking.
		if reFuncStart.MatchString(line) {
			if inFunc && funcLineCount > 50 {
				resp.Finding(
					"RISK-005",
					sdk.SeverityLow,
					sdk.ConfidenceHigh,
					fmt.Sprintf("Long function detected (%d lines): increases maintenance risk", funcLineCount),
				).
					At(filePath, funcStartLine, funcStartLine+funcLineCount).
					WithMetadata("risk_type", "complexity").
					WithMetadata("line_count", fmt.Sprintf("%d", funcLineCount)).
					Done()
			}
			inFunc = true
			funcStartLine = lineNum
			funcLineCount = 0
			maxNesting = 0
			currentNesting = 0
		}

		if inFunc {
			funcLineCount++
			trimmed := strings.TrimSpace(line)

			// Track nesting depth.
			if reNestedConditional.MatchString(line) {
				// Count leading indentation as proxy for nesting depth.
				indent := len(line) - len(strings.TrimLeft(line, " \t"))
				// Normalize tabs to 4 spaces.
				tabCount := strings.Count(line[:indent], "\t")
				spaceCount := indent - tabCount
				normalizedIndent := tabCount*4 + spaceCount
				depth := normalizedIndent / 4

				if depth > currentNesting {
					currentNesting = depth
				}
				if currentNesting > maxNesting {
					maxNesting = currentNesting
				}
			}

			// Check for deep nesting.
			if maxNesting >= 4 && (trimmed == "}" || trimmed == "end" || trimmed == "") {
				// Emit once when we detect deep nesting in a function.
				if maxNesting >= 4 {
					resp.Finding(
						"RISK-005",
						sdk.SeverityLow,
						sdk.ConfidenceHigh,
						fmt.Sprintf("Deeply nested conditional logic (depth %d): increases cognitive complexity", maxNesting),
					).
						At(filePath, funcStartLine, lineNum).
						WithMetadata("risk_type", "nesting_depth").
						WithMetadata("max_depth", fmt.Sprintf("%d", maxNesting)).
						Done()
					maxNesting = 0 // Reset to avoid duplicate findings.
				}
			}
		}
	}

	// Check the last function in the file.
	if inFunc && funcLineCount > 50 {
		resp.Finding(
			"RISK-005",
			sdk.SeverityLow,
			sdk.ConfidenceHigh,
			fmt.Sprintf("Long function detected (%d lines): increases maintenance risk", funcLineCount),
		).
			At(filePath, funcStartLine, funcStartLine+funcLineCount).
			WithMetadata("risk_type", "complexity").
			WithMetadata("line_count", fmt.Sprintf("%d", funcLineCount)).
			Done()
	}
}

// checkSecurityDebt checks for RISK-001: security-related TODO/FIXME/HACK/XXX comments.
func checkSecurityDebt(resp *sdk.ResponseBuilder, filePath string, lineNum int, line string) {
	if reSecurityTODO.MatchString(line) {
		resp.Finding(
			"RISK-001",
			sdk.SeverityHigh,
			sdk.ConfidenceMedium,
			fmt.Sprintf("Security-related technical debt: %s", strings.TrimSpace(line)),
		).
			At(filePath, lineNum, lineNum).
			WithMetadata("risk_type", "tech_debt").
			Done()
	}
}

// checkDeprecatedAPI checks for RISK-002: deprecated API usage.
func checkDeprecatedAPI(resp *sdk.ResponseBuilder, filePath string, lineNum int, line, ext string) {
	var matched bool
	var detail string

	switch ext {
	case ".go":
		if reDeprecatedGo.MatchString(line) {
			matched = true
			detail = "Go deprecated API"
		}
	case ".py":
		if reDeprecatedPython.MatchString(line) {
			matched = true
			detail = "Python deprecated pattern"
		}
	case ".js", ".ts", ".jsx", ".tsx":
		if reDeprecatedJS.MatchString(line) {
			matched = true
			detail = "JavaScript deprecated API"
		}
	}

	if matched {
		resp.Finding(
			"RISK-002",
			sdk.SeverityMedium,
			sdk.ConfidenceHigh,
			fmt.Sprintf("Deprecated API usage detected (%s): %s", detail, strings.TrimSpace(line)),
		).
			At(filePath, lineNum, lineNum).
			WithMetadata("risk_type", "deprecated_api").
			WithMetadata("language", ext).
			Done()
	}
}

// emitWorkspaceRisks emits workspace-level risk findings for RISK-003 and RISK-004.
func emitWorkspaceRisks(resp *sdk.ResponseBuilder, rc *riskContext) {
	// RISK-003: Single point of failure.
	if rc.hasDBConnection && !rc.hasPooling && !rc.hasFallback {
		resp.Finding(
			"RISK-003",
			sdk.SeverityHigh,
			sdk.ConfidenceHigh,
			"Single point of failure: database connection without pooling or fallback mechanism",
		).
			At(rc.dbFile, rc.dbLine, rc.dbLine).
			WithMetadata("risk_type", "single_point_of_failure").
			WithMetadata("resource", "database").
			Done()
	}

	// RISK-004: Missing error recovery.
	if rc.hasExternalCalls && !rc.hasRetryMech {
		resp.Finding(
			"RISK-004",
			sdk.SeverityMedium,
			sdk.ConfidenceMedium,
			"External service calls detected without retry or circuit breaker mechanism",
		).
			At(rc.externalCallFile, rc.externalCallLine, rc.externalCallLine).
			WithMetadata("risk_type", "missing_recovery").
			Done()
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-risk-register: %v\n", err)
		return 1
	}
	return 0
}
