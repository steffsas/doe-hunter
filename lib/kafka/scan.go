package kafka

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type BasicKafkaScan struct {
	ScanId       string `json:"scan_id"`
	RunId        string `json:"run_id"`
	RootScanId   string `json:"root_scan_id"`
	ParentScanId string `json:"parent_scan_id"`

	OnBlocklist bool      `json:"on_blocklist"`
	Host        string    `json:"host"`
	Scheduled   time.Time `json:"scheduled"`
}

func generateScanId() string {
	return uuid.New().String()
}

func (scan *BasicKafkaScan) GetHost() string {
	return scan.Host
}

func (scan *BasicKafkaScan) GetScheduled() time.Time {
	return scan.Scheduled
}

func (scan *BasicKafkaScan) Marshall() ([]byte, error) {
	return json.Marshal(scan)
}

func (scan *BasicKafkaScan) GetScanId() string {
	return scan.ScanId
}

func (scan *BasicKafkaScan) GetRunId() string {
	return scan.RunId
}

func (scan *BasicKafkaScan) GetRootScanId() string {
	return scan.RootScanId
}

func (scan *BasicKafkaScan) GetParentScanId() string {
	return scan.ParentScanId
}

func (scan *BasicKafkaScan) IsOnBlocklist() bool {
	return scan.OnBlocklist
}

type KafkaScan interface {
	GetScanId() string
	GetRunId() string
	GetParentScanId() string
	GetRootScanId() string
	GetHost() string
	GetScheduled() time.Time
	Marshall() ([]byte, error)
	IsOnBlocklist() bool
}

func NewBasicKafkaScan(runId, rootScanId, parentScanId, host string, onBlockList bool) *BasicKafkaScan {
	return &BasicKafkaScan{
		ScanId:       generateScanId(),
		RunId:        runId,
		RootScanId:   rootScanId,
		ParentScanId: parentScanId,
		Host:         host,
		Scheduled:    time.Now(),
		OnBlocklist:  onBlockList,
	}
}
