package scan

import (
	"github.com/steffsas/doe-hunter/lib/query"
)

type DDRScanMetaInformation struct {
	ScanMetaInformation
	ScheduleDoEScans bool `json:"schedule_doe_scans"`
}

type DDRScan struct {
	Meta   *DDRScanMetaInformation        `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func NewDDRScan(host string, port int, scheduleDoEScans bool) *DDRScan {
	defaultQuery := query.NewDDRQuery()
	defaultQuery.Host = host
	defaultQuery.Port = port

	ddrScan := &DDRScan{
		Meta: &DDRScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
			ScheduleDoEScans: scheduleDoEScans,
		},
		Query: defaultQuery,
	}

	ddrScan.Meta.GenerateScanID()

	return ddrScan
}
