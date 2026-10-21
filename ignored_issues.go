package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

var (
	ignoredIssuesData = make(map[string]bool)
	ignoredIssuesMutex sync.RWMutex
)

const ignoredIssuesFile = "ignored_issues.json"

// LoadIgnoredIssues loads the list of ignored issue IDs from file
func LoadIgnoredIssues() {
	data, err := os.ReadFile(ignoredIssuesFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error loading ignored issues: %v\n", err)
		}
		return
	}

	ignoredIssuesMutex.Lock()
	defer ignoredIssuesMutex.Unlock()
	
	if err := json.Unmarshal(data, &ignoredIssuesData); err != nil {
		fmt.Printf("Error parsing ignored issues: %v\n", err)
	}
}

// SaveIgnoredIssues saves the current ignore list to file
func SaveIgnoredIssues() {
	ignoredIssuesMutex.RLock()
	data, err := json.MarshalIndent(ignoredIssuesData, "", "  ")
	ignoredIssuesMutex.RUnlock()
	
	if err != nil {
		fmt.Printf("Error marshaling ignored issues: %v\n", err)
		return
	}
	
	if err := os.WriteFile(ignoredIssuesFile, data, 0644); err != nil {
		fmt.Printf("Error saving ignored issues: %v\n", err)
	}
}

// IgnoreIssue adds an issue ID to the ignore list
func IgnoreIssue(issueID string) {
	ignoredIssuesMutex.Lock()
	ignoredIssuesData[issueID] = true
	ignoredIssuesMutex.Unlock()
	SaveIgnoredIssues()
	fmt.Printf("[Ignore] Issue ID %s is now ignored.\n", issueID)
}

// UnignoreIssue removes an issue ID from the ignore list (e.g. for re-verification)
func UnignoreIssue(issueID string) {
	ignoredIssuesMutex.Lock()
	delete(ignoredIssuesData, issueID)
	ignoredIssuesMutex.Unlock()
	SaveIgnoredIssues()
	fmt.Printf("[Verify] Issue ID %s is un-ignored for verification.\n", issueID)
}

// IsIssueIgnored checks if an issue ID is currently ignored
func IsIssueIgnored(issueID string) bool {
	ignoredIssuesMutex.RLock()
	defer ignoredIssuesMutex.RUnlock()
	return ignoredIssuesData[issueID]
}

func init() {
	LoadIgnoredIssues()
}
