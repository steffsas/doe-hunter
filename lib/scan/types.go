package scan

import (
	"time"

	"github.com/google/uuid"
)

type ScanMetaInformation struct {
	ScanID       string `json:"scan_id"`
	ParentScanID string `json:"parent_scan_id"`
	RootScanID   string `json:"root_scan_id"`

	Scheduled time.Time `json:"scheduled"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`

	Errors []error `json:"errors"`
}

func (smi *ScanMetaInformation) GenerateScanID() {
	smi.ScanID = uuid.New().String()
}

func (smi *ScanMetaInformation) AddError(err error) {
	smi.Errors = append(smi.Errors, err)
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
