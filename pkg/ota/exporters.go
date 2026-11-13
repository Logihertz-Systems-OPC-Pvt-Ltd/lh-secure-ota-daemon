package ota

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatTerminalTable formats the audit report into a clean, human-readable terminal table
func FormatTerminalTable(report *AuditReport) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("========================================================================================\n")
	sb.WriteString("            LOGIHERTZ SECURE OTA DAEMON: POSTURE AUDIT REPORT (lh-ota)          \n")
	sb.WriteString("========================================================================================\n")
	sb.WriteString(fmt.Sprintf(" Timestamp (UTC) : %s\n", report.TimestampUTC))
	sb.WriteString(fmt.Sprintf(" Posture Score   : %d / 100\n", report.Score))
	sb.WriteString(fmt.Sprintf(" Security Status : %s\n", report.Status))
	sb.WriteString(fmt.Sprintf(" Total Invariants: %d | Passed: %d | Failed: %d\n",
		report.TotalRules, report.PassedRules, report.FailedRules))
	sb.WriteString("----------------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf(" %-12s | %-8s | %-5s | %-8s | %s\n", "RULE ID", "STATUS", "DEDUCT", "SEVERITY", "TITLE"))
	sb.WriteString("----------------------------------------------------------------------------------------\n")

	for _, f := range report.Findings {
		statusStr := "[PASS]"
		if !f.Passed {
			statusStr = "[FAIL]"
		}
		deductStr := fmt.Sprintf("-%d", f.Deduction)
		if f.Passed {
			deductStr = " 0"
		}

		sb.WriteString(fmt.Sprintf(" %-12s | %-8s | %-6s | %-8s | %s\n",
			f.RuleID, statusStr, deductStr, f.Severity, f.Title))
	}
	sb.WriteString("----------------------------------------------------------------------------------------\n")

	if report.FailedRules > 0 {
		sb.WriteString("\nDETAILED REMEDIATION ACTIONS REQUIRED:\n")
		for _, f := range report.Findings {
			if !f.Passed {
				sb.WriteString(fmt.Sprintf(" -> [%s] (%s, %s): %s\n", f.RuleID, f.Severity, f.CWENumber, f.Title))
				sb.WriteString(fmt.Sprintf("    Issue:       %s\n", f.Description))
				sb.WriteString(fmt.Sprintf("    Remediation: %s\n\n", f.Remediation))
			}
		}
	} else {
		sb.WriteString("\nAll 10 embedded OTA security invariants satisfied. Target firmware pipeline is HARDENED.\n")
	}
	sb.WriteString("========================================================================================\n")

	return sb.String()
}

// FormatCanonicalJSON serializes the audit report into formatted JSON
func FormatCanonicalJSON(report *AuditReport) (string, error) {
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize audit report to JSON: %w", err)
	}
	return string(bytes), nil
}

// SarifSchema defines the root object of an OASIS SARIF v2.1.0 document
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     SarifMultiformatText `json:"shortDescription"`
	FullDescription      SarifMultiformatText `json:"fullDescription"`
	DefaultConfiguration SarifRuleConfig      `json:"defaultConfiguration"`
	HelpURI              string               `json:"helpUri"`
}

type SarifRuleConfig struct {
	Level string `json:"level"`
}

type SarifMultiformatText struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID    string               `json:"ruleId"`
	Level     string               `json:"level"`
	Message   SarifMultiformatText `json:"message"`
	Locations []SarifLocation      `json:"locations,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

// FormatSARIF transforms the AuditReport into standard OASIS SARIF v2.1.0
func FormatSARIF(report *AuditReport) (string, error) {
	var sarifRules []SarifRule
	var sarifResults []SarifResult

	for _, f := range report.Findings {
		level := "note"
		switch f.Severity {
		case SeverityCritical, SeverityHigh:
			level = "error"
		case SeverityMedium:
			level = "warning"
		case SeverityLow:
			level = "note"
		}

		sarifRules = append(sarifRules, SarifRule{
			ID:   f.RuleID,
			Name: f.Title,
			ShortDescription: SarifMultiformatText{
				Text: f.Title,
			},
			FullDescription: SarifMultiformatText{
				Text: fmt.Sprintf("[%s] %s (Remediation: %s)", f.CWENumber, f.Description, f.Remediation),
			},
			DefaultConfiguration: SarifRuleConfig{
				Level: level,
			},
			HelpURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon",
		})

		if !f.Passed {
			sarifResults = append(sarifResults, SarifResult{
				RuleID: f.RuleID,
				Level:  level,
				Message: SarifMultiformatText{
					Text: fmt.Sprintf("%s (%s): %s. Action: %s", f.Title, f.CWENumber, f.Description, f.Remediation),
				},
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{
								URI: "config/ota_policy.json",
							},
						},
					},
				},
			})
		}
	}

	sarifDoc := SarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SarifRun{
			{
				Tool: SarifTool{
					Driver: SarifDriver{
						Name:           "lh-ota",
						Version:        "0.1.0",
						InformationURI: "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secure-ota-daemon",
						Rules:          sarifRules,
					},
				},
				Results: sarifResults,
			},
		},
	}

	bytes, err := json.MarshalIndent(sarifDoc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize SARIF report: %w", err)
	}
	return string(bytes), nil
}
