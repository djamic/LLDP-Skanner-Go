package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// CaptureSession represents a network capture session
type CaptureSession struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Config    string    `json:"config"`
	Status    string    `json:"status"` // "running", "completed", "failed"
}

// FullCaptureData represents the complete data set for a session
type FullCaptureData struct {
	Session     CaptureSession    `json:"session"`
	Topology    GraphData         `json:"topology"`
	Metrics     []TrafficMetrics  `json:"metrics"`
	Events      []StatusEvent     `json:"events"`
	DevicesData []DeviceData      `json:"devices_data"` // Per-device SNMP data
}

// TrafficMetrics holds traffic data for a specific point in time
type TrafficMetrics struct {
	Timestamp   time.Time `json:"timestamp"`
	DeviceIP    string    `json:"device_ip"`
	Interface   string    `json:"interface"`
	InBps       uint64    `json:"in_bps"`
	OutBps      uint64    `json:"out_bps"`
	InDiscards  uint64    `json:"in_discards"`
	OutDiscards uint64    `json:"out_discards"`
	InErrors    uint64    `json:"in_errors"`
	OutErrors   uint64    `json:"out_errors"`
	OperStatus  int       `json:"oper_status"`
}

// StatusEvent represents a status change event
type StatusEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	DeviceIP    string    `json:"device_ip"`
	Interface   string    `json:"interface"`
	OldStatus   int       `json:"old_status"`
	NewStatus   int       `json:"new_status"`
	Description string    `json:"description"`
}

// CaptureManager manages capture sessions
type CaptureManager struct {
	paramDir       string
	activeSession  *CaptureSession
	activeTopology *GraphData
	mu             sync.Mutex
}

// Global instance
var globalCaptureManager *CaptureManager

// InitCaptureManager initializes the capture manager
func InitCaptureManager(baseDir string) error {
	captureDir := filepath.Join(baseDir, "captures")
	if err := os.MkdirAll(captureDir, 0755); err != nil {
		return fmt.Errorf("failed to create captures directory: %v", err)
	}

	globalCaptureManager = &CaptureManager{
		paramDir: captureDir,
	}
	return nil
}

// StartCapture starts a new capture session
func (cm *CaptureManager) StartCapture(name string, graph *DJGraph) (string, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.activeSession != nil {
		return "", fmt.Errorf("a capture session is already running: %s", cm.activeSession.ID)
	}

	sessionID := uuid.New().String()
	if name == "" {
		name = fmt.Sprintf("Capture %s", time.Now().Format("2006-01-02 15:04:05"))
	}

	// Capture current topology
	topoData := graph.GetGraphData()

	cm.activeSession = &CaptureSession{
		ID:        sessionID,
		Name:      name,
		StartTime: time.Now(),
		Status:    "running",
	}
	cm.activeTopology = &topoData

	fmt.Printf("🔴 Capture started: %s (%s)\n", name, sessionID)
	return sessionID, nil
}

// StopCapture stops the active session and saves data
func (cm *CaptureManager) StopCapture() (string, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.activeSession == nil {
		return "", fmt.Errorf("no active capture session")
	}

	session := cm.activeSession
	session.EndTime = time.Now()
	session.Status = "completed"

	// Fetch metrics from InfluxDB for the duration
	fmt.Printf("⏳ Fetching metrics for session %s...\n", session.ID)
	metrics, events, err := cm.fetchSessionData(session.StartTime, session.EndTime)
	if err != nil {
		fmt.Printf("⚠️ Failed to fetch complete metrics: %v\n", err)
		// Proceed anyway, maybe partial data
	}

	fullData := FullCaptureData{
		Session:  *session,
		Topology: *cm.activeTopology,
		Metrics:  metrics,
		Events:   events,
	}

	// Save to file
	filename := filepath.Join(cm.paramDir, fmt.Sprintf("%s_full_data.json", session.ID))
	file, err := os.Create(filename)
	if err != nil {
		return "", fmt.Errorf("failed to create capture file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fullData); err != nil {
		return "", fmt.Errorf("failed to encode capture data: %v", err)
	}

	cm.activeSession = nil
	cm.activeTopology = nil

	fmt.Printf("✅ Capture saved to %s\n", filename)
	return session.ID, nil
}

// ListCaptures returns a list of available captures
func (cm *CaptureManager) ListCaptures() ([]CaptureSession, error) {
	files, err := filepath.Glob(filepath.Join(cm.paramDir, "*_full_data.json"))
	if err != nil {
		return nil, err
	}

	var sessions []CaptureSession
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		
		// optimized: just decode structure enough to get session info
		// In a real implementation we might keep a separate index file
		var data struct {
			Session CaptureSession `json:"session"`
		}
		decoder := json.NewDecoder(file)
		if err := decoder.Decode(&data); err == nil {
			sessions = append(sessions, data.Session)
		}
		file.Close()
	}
	return sessions, nil
}

// LoadCapture errors: the id is not a plain name, or no session has it.
var (
	errAnalyzerCaptureID       = errors.New("invalid session id")
	errAnalyzerCaptureNotFound = errors.New("session file not found")
)

// LoadCapture reads the saved data of a capture session. The id must be a
// plain file name part, so a request cannot read outside the capture
// directory.
func (cm *CaptureManager) LoadCapture(sessionID string) (FullCaptureData, error) {
	var data FullCaptureData
	if sessionID == "" || filepath.Base(sessionID) != sessionID {
		return data, fmt.Errorf("%w %q", errAnalyzerCaptureID, sessionID)
	}
	file, err := os.Open(filepath.Join(cm.paramDir, sessionID+"_full_data.json"))
	if errors.Is(err, os.ErrNotExist) {
		return data, fmt.Errorf("%w: %v", errAnalyzerCaptureNotFound, err)
	}
	if err != nil {
		return data, err
	}
	defer file.Close()
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return data, fmt.Errorf("failed to decode session data: %v", err)
	}
	return data, nil
}

// ActiveSession returns the current running session (or nil)
func (cm *CaptureManager) ActiveSession() *CaptureSession {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.activeSession
}

// fetchSessionData retrieves metrics from InfluxDB
func (cm *CaptureManager) fetchSessionData(start, end time.Time) ([]TrafficMetrics, []StatusEvent, error) {
	return QueryRangeMetrics(start, end)
}
