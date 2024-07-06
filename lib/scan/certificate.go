package scan

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/steffsas/doe-hunter/lib/query"
)

const CERTIFICATE_SCAN_TYPE = "certificate"

type CertificateScanMetaInformation struct {
	ScanMetaInformation
}

type CertificateScan struct {
	Scan

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

func (scan *CertificateScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *CertificateScan) GetType() string {
	return CERTIFICATE_SCAN_TYPE
}

func (scan *CertificateScan) GetIdentifier() string {
	// host, port, protocol, alpn
	// tls_skip_verify is not part of the identifier because we will get the certificate in a second query if certificate is not valid

	alpn := scan.Query.ALPN

	// sort alpn first
	if len(alpn) < 1 {
		scan.Query.ALPN = []string{"no_alpn"}
	} else {
		// sort alpn
		slices.Sort(scan.Query.ALPN)
	}
	return fmt.Sprintf("%s|%s|%d|%s|%s",
		CERTIFICATE_SCAN_TYPE,
		scan.Query.Host,
		scan.Query.Port,
		scan.Query.Protocol,
		scan.Query.ALPN)
}

func NewCertificateScan(q *query.CertificateQuery, rootScanId, parentScanId, runId, vantagePoint string) *CertificateScan {
	if q == nil {
		q = query.NewCertificateQuery()
	}
	scan := &CertificateScan{
		Meta: &CertificateScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Query = q
	return scan
}
