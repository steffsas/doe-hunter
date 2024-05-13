package scan

import "github.com/steffsas/doe-hunter/lib/query"

type DoQScanMetaInformation struct {
	ScanMetaInformation
}

type DoQScan struct {
	Meta   *DoQScanMetaInformation `json:"meta"`
	Query  *query.DoQQuery         `json:"query"`
	Result *query.DoQResponse      `json:"result"`
}

func NewDoQScan(host string, port int) *DoQScan {
	defaultQuery := query.NewDoQQuery()
	defaultQuery.Host = host
	defaultQuery.Port = port

	scan := &DoQScan{
		Meta: &DoQScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
		},
		Query: defaultQuery,
	}

	scan.Meta.GenerateScanID()

	return scan
}
