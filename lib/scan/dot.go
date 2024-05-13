package scan

import "github.com/steffsas/doe-hunter/lib/query"

type DoTScanMetaInformation struct {
	ScanMetaInformation
}

type DoTScan struct {
	Meta   *DoTScanMetaInformation `json:"meta"`
	Query  *query.DoTQuery         `json:"query"`
	Result *query.DoTResponse      `json:"result"`
}

func NewDoTScan(host string, port int) *DoTScan {
	defaultQuery := query.NewDoTQuery()
	defaultQuery.Host = host
	defaultQuery.Port = port

	scan := &DoTScan{
		Meta: &DoTScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
		},
		Query: defaultQuery,
	}

	scan.Meta.GenerateScanID()

	return scan
}
