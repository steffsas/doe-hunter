package scan

import (
	"encoding/json"

	"github.com/steffsas/doe-hunter/lib/query"
)

const DOH_SCAN_TYPE = "DoH"

type DoHScanMetaInformation struct {
	ScanMetaInformation
}

type DoHScan struct {
	Scan

	Meta   *DoHScanMetaInformation `json:"meta"`
	Query  *query.DoHQuery         `json:"query"`
	Result *query.DoHResponse      `json:"result"`
}

func (scan *DoHScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DoHScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *DoHScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DoHScan) GetType() string {
	return DOH_SCAN_TYPE
}

func (scan *DoHScan) GetDoEQuery() *query.DoEQuery {
	return &scan.Query.DoEQuery
}

func NewDoHScan(q *query.DoHQuery, parentScanId, rootScanId, runId, vantagePoint string) *DoHScan {
	if q == nil {
		q = query.NewDoHQuery()
	}

	scan := &DoHScan{
		Meta: &DoHScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)

	scan.Query = q

	return scan
}
