package scan

import (
	"encoding/json"
	"fmt"

	"github.com/steffsas/doe-hunter/lib/query"
)

const DOT_SCAN_TYPE = "DoT"

type DoTScanMetaInformation struct {
	ScanMetaInformation
}

type DoTScan struct {
	DoEScan

	Meta   *DoTScanMetaInformation `json:"meta"`
	Query  *query.DoTQuery         `json:"query"`
	Result *query.DoTResponse      `json:"result"`
}

func (scan *DoTScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DoTScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *DoTScan) GetType() string {
	return DOT_SCAN_TYPE
}

func (scan *DoTScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DoTScan) GetDoEQuery() *query.DoEQuery {
	return &scan.Query.DoEQuery
}

func (scan *DoTScan) GetIdentifier() string {
	// host, port
	return fmt.Sprintf("%s|%s|%d|skip_tls_verify_%t",
		DOT_SCAN_TYPE,
		scan.Query.Host,
		scan.Query.Port,
		scan.Query.SkipCertificateVerify)
}

func NewDoTScan(q *query.DoTQuery, parentScanId, rootScanId, runId, vantagePoint string) *DoTScan {
	if q == nil {
		q = query.NewDoTQuery()
	}

	scan := &DoTScan{
		Meta: &DoTScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Query = q

	return scan
}
