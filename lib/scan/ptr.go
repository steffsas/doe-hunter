package scan

import (
	"encoding/json"

	"github.com/steffsas/doe-hunter/lib/query"
)

const PTR_SCAN_TYPE = "PTR"

type PTRScanMetaInformation struct {
	ScanMetaInformation
}

type PTRScan struct {
	Scan

	Meta   *PTRScanMetaInformation        `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func (scan *PTRScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *PTRScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *PTRScan) GetType() string {
	return PTR_SCAN_TYPE
}

func NewPTRScan(q *query.ConventionalDNSQuery, parentScanId, rootScanId, runId string) *PTRScan {
	var ptrQ *query.PTRQuery
	if q == nil {
		ptrQ = query.NewPTRQuery()
	} else {
		ptrQ = &query.PTRQuery{}
		ptrQ.ConventionalDNSQuery = *q
	}

	scan := &PTRScan{
		Meta: &PTRScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId)
	scan.Query = &ptrQ.ConventionalDNSQuery

	return scan
}
