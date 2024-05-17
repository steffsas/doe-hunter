package scan

import (
	"time"

	"github.com/google/uuid"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
)

type ScanIds struct {
	ScanId string `json:"scan_id"`
}

type ScanMetaInformation struct {
	ScanId       string `json:"scan_id"`
	ParentScanId string `json:"parent_scan_id"`
	RootScanId   string `json:"root_scan_id"`
	VantagePoint string `json:"vantage_point"`

	Scheduled time.Time `json:"scheduled"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`

	Errors []custom_errors.DoEErrors `json:"errors"`
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
}

type DoEScan interface {
	Scan

	GetDoEQuery() *query.DoEQuery
}

func NewScanMetaInformation(parentScanId, rootScanId string) *ScanMetaInformation {
	meta := &ScanMetaInformation{
		ParentScanId: parentScanId,
		RootScanId:   rootScanId,
		Errors:       []custom_errors.DoEErrors{},
	}

	meta.GenerateScanId()
	meta.SetScheduled()

	return meta
}
