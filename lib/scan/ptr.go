package scan

import (
	"encoding/json"
	"fmt"

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

func (scan *PTRScan) GetIdentifier() string {
	// host, port
	return fmt.Sprintf("%s|%s|%d",
		PTR_SCAN_TYPE,
		scan.Query.Host,
		scan.Query.Port)
}

// TODO: Just pass meta information as a struct
func NewPTRScan(q *query.ConventionalDNSQuery, parentScanId, rootScanId, runId, vantagePoint string) *PTRScan {
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
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Query = &ptrQ.ConventionalDNSQuery

	return scan
}
