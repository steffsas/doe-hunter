package scan

import (
	"encoding/json"

	"github.com/steffsas/doe-hunter/lib/query"
)

const DOQ_SCAN_TYPE = "DoQ"

type DoQScanMetaInformation struct {
	ScanMetaInformation
}

type DoQScan struct {
	Meta   *DoQScanMetaInformation `json:"meta"`
	Query  *query.DoQQuery         `json:"query"`
	Result *query.DoQResponse      `json:"result"`
}

func (scan *DoQScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DoQScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DoQScan) GetType() string {
	return DOQ_SCAN_TYPE
}

func NewDoQScan(q *query.DoQQuery, parentScanId, rootScanId string) *DoQScan {
	if q == nil {
		q = query.NewDoQQuery()
	}

	scan := &DoQScan{
		Meta: &DoQScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId)
	scan.Query = q

	return scan
}
