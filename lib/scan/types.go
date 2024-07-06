package scan

import (
	"time"

	"github.com/google/uuid"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
)

type ScanMetaInformation struct {
	// RunId is a unique identifier for a set of scans
	RunId string `json:"run_id"`

	// ScanId is a unique identifier for a single scan
	ScanId string `json:"scan_id"`

	// IsOnBlocklist is true if the scan is on the blocklist
	IsOnBlocklist bool `json:"is_on_blocklist"`

	// ParentScanId is the scan id of the scan that triggered this scan
	ParentScanId string `json:"parent_scan_id"`

	// RootScanId is the scan id of the scan that started the scan chain
	RootScanId string `json:"root_scan_id"`

	// VantagePoint is the vantage point from which the scan was started
	VantagePoint string `json:"vantage_point"`

	// Scheduled is the time when the scan was scheduled, i.e., when the scan was created and scheduled to kafka
	Scheduled time.Time `json:"scheduled"`

	// Started is the time when the scan was started
	Started time.Time `json:"started"`

	// Finished is the time when the scan was finished
	Finished time.Time `json:"finished"`

	// the children scans of this scan (DoE, PTR, EDSR, ...)
	Children []string `json:"children"`

	// Errors is a list of errors that occurred during the scan
	Errors []custom_errors.DoEErrors `json:"errors"`
}

func (smi *ScanMetaInformation) GenerateRunId() {
	smi.RunId = uuid.New().String()
}

func (smi *ScanMetaInformation) GenerateScanId() {
	smi.ScanId = uuid.New().String()
}

func (smi *ScanMetaInformation) AddError(err ...custom_errors.DoEErrors) {
	smi.Errors = append(smi.Errors, err...)
}

func (smi *ScanMetaInformation) SetScheduled() {
	smi.Scheduled = time.Now()
}

func (smi *ScanMetaInformation) SetStarted() {
	smi.Started = time.Now()
}

func (smi *ScanMetaInformation) SetFinished() {
	smi.Finished = time.Now()
}

func (smi *ScanMetaInformation) Schedule() {
	smi.SetScheduled()
	smi.GenerateScanId()
}

type Scan interface {
	GetType() string
	GetMetaInformation() *ScanMetaInformation
	Marshall() ([]byte, error)
	GetIdentifier() string
}

type DoEScan interface {
	Scan

	GetDoEQuery() *query.DoEQuery
}

func NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint string) *ScanMetaInformation {
	meta := &ScanMetaInformation{
		RunId:        runId,
		ParentScanId: parentScanId,
		RootScanId:   rootScanId,
		VantagePoint: vantagePoint,
		Errors:       []custom_errors.DoEErrors{},
	}

	meta.IsOnBlocklist = false

	meta.GenerateScanId()
	meta.SetScheduled()

	return meta
}
