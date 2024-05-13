package scan

import "github.com/steffsas/doe-hunter/lib/query"

type DoHScanMetaInformation struct {
	ScanMetaInformation
}

type DoHScan struct {
	Meta   *DoHScanMetaInformation `json:"meta"`
	Query  *query.DoHQuery         `json:"query"`
	Result *query.DoHResponse      `json:"result"`
}

func NewDoHScan(host string, port int, uri string) *DoHScan {
	defaultQuery := query.NewDoHQuery()
	defaultQuery.Host = host
	defaultQuery.Port = port
	defaultQuery.URI = "/dns-query{?dns}"

	if uri != "" {
		defaultQuery.URI = uri
	}

	scan := &DoHScan{
		Meta: &DoHScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
		},
		Query: defaultQuery,
	}

	scan.Meta.GenerateScanID()

	return scan
}
