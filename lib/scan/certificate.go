package scan

import (
	"encoding/json"

	"github.com/steffsas/doe-hunter/lib/query"
)

const CERTIFICATE_SCAN_TYPE = "certificate"

type CertificateScanMetaInformation struct {
	ScanMetaInformation
}

type CertificateScan struct {
	Meta   *CertificateScanMetaInformation `json:"meta"`
	Query  *query.CertificateQuery         `json:"query"`
	Result *query.CertificateResponse      `json:"result"`
}

func (scan *CertificateScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *CertificateScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *CertificateScan) GetType() string {
	return CERTIFICATE_SCAN_TYPE
}

func NewCertificateScan(query *query.CertificateQuery, rootScanId string, parentScanId string) *CertificateScan {
	scan := &CertificateScan{
		Meta: &CertificateScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(rootScanId, parentScanId)
	scan.Query = query
	return scan
}
