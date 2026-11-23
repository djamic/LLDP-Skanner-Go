package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHealthTiers: one table (healthTiers) names and colours a health
// score wherever it is shown: the console and Telegram (GetHealthLabel),
// the audit Markdown and the Word report. A score of 60 is "Fair"
// everywhere, where the reports called it "Critical".
func TestHealthTiers(t *testing.T) {
	for score, want := range map[int]string{
		100: "Excellent", 90: "Excellent", 89: "Good", 70: "Good", 69: "Fair", 50: "Fair",
		49: "Poor", 30: "Poor", 29: "Critical", 0: "Critical", -5: "Critical",
	} {
		if got := GetHealthLabel(score); got != want {
			t.Errorf("GetHealthLabel(%d) = %q, want %q", score, got, want)
		}
	}
	for i := 1; i < len(healthTiers); i++ {
		if healthTiers[i].Min >= healthTiers[i-1].Min {
			t.Errorf("healthTiers are not best first: %+v after %+v", healthTiers[i], healthTiers[i-1])
		}
	}

	resetState(t)
	SetLastReport(60, nil, 0)
	fair := healthTierOf(60)
	if md := generateAuditMD([]string{"switch"}); !strings.Contains(md, "**60/100** — Fair") {
		t.Errorf("audit Markdown does not call 60 Fair:\n%s", md[:min(len(md), 600)])
	}
	rec := httptest.NewRecorder()
	reportFullHandler(rec, httptest.NewRequest("GET", "/api/report/full", nil))
	if body := rec.Body.String(); !strings.Contains(body, fair.Label) || !strings.Contains(body, fair.Color) {
		t.Errorf("Word report does not show 60 as %s in %s", fair.Label, fair.Color)
	}
}
