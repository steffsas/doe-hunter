package scan

import "github.com/steffsas/doe-hunter/lib/query"

type PTRScanMetaInformation struct {
	ScanMetaInformation
}

type PTRScan struct {
	Meta   *PTRScanMetaInformation        `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func NewPTRScan(host string, port int, resolveIP string) (scan *PTRScan, err error) {
	scan = &PTRScan{
		Meta: &PTRScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
		},
	}

	defaultQuery, err := query.NewPTRQuery(host, resolveIP)
	if err != nil {
		return
	}
	defaultQuery.Port = port

	scan.Query = defaultQuery
	scan.Meta.GenerateScanID()

	return
}
