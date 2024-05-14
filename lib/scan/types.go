package scan

import (
	"time"

	"github.com/google/uuid"
)

type ScanMetaInformation struct {
	ScanId       string `json:"scan_id"`
	ParentScanId string `json:"parent_scan_id"`
	RootScanId   string `json:"root_scan_id"`

	Scheduled time.Time `json:"scheduled"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`

	Errors []string `json:"errors"`
}

func (smi *ScanMetaInformation) GenerateScanId() {
	smi.ScanId = uuid.New().String()
}

func (smi *ScanMetaInformation) AddError(err ...error) {
	for _, e := range err {
		smi.Errors = append(smi.Errors, e.Error())
	}
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
	GetScanId() string
	Marshall() ([]byte, error)
}

func NewScanMetaInformation(parentScanId, rootScanId string) *ScanMetaInformation {
	meta := &ScanMetaInformation{
		ParentScanId: parentScanId,
		RootScanId:   rootScanId,
		Errors:       []string{},
	}

	meta.GenerateScanId()
	meta.SetScheduled()

	return meta
}
