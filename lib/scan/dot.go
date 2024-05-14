package scan

import (
	"encoding/json"

	"github.com/steffsas/doe-hunter/lib/query"
)

const DOT_SCAN_TYPE = "DoT"

type DoTScanMetaInformation struct {
	ScanMetaInformation
}

type DoTScan struct {
	Meta   *DoTScanMetaInformation `json:"meta"`
	Query  *query.DoTQuery         `json:"query"`
	Result *query.DoTResponse      `json:"result"`
}

func (scan *DoTScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DoTScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DoTScan) GetType() string {
	return DOT_SCAN_TYPE
}

func NewDoTScan(q *query.DoTQuery, parentScanId, rootScanId string) *DoTScan {
	if q == nil {
		q = query.NewDoTQuery()
	}

	scan := &DoTScan{
		Meta: &DoTScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId)
	scan.Query = q

	return scan
}
