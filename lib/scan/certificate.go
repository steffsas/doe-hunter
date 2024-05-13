package scan

import "github.com/steffsas/doe-hunter/lib/query"

type CertificateScanMetaInformation struct {
	ScanMetaInformation
}

type CertificateScan struct {
	Meta   *CertificateScanMetaInformation `json:"meta"`
	Query  *query.CertificateQuery         `json:"query"`
	Result *query.CertificateResponse      `json:"result"`
}

func NewCertificateScan(host string, port int) *CertificateScan {
	defaultQuery := query.NewCertificateQuery()
	defaultQuery.Host = host
	defaultQuery.Port = port

	scan := &CertificateScan{
		Meta: &CertificateScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
		},
		Query: defaultQuery,
	}

	scan.Meta.GenerateScanID()

	return scan
}
