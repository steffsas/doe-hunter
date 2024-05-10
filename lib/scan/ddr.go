package scan

import (
	"github.com/steffsas/doe-hunter/lib/query"
)

type DDRScanMetaInformation struct {
	ScanMetaInformation
	ScheduleDoEScans bool `json:"schedule_doe_scans"`
}

type DDRScan struct {
	Meta   DDRScanMetaInformation        `json:"meta"`
	Scan   query.ConventionalDNSQuery    `json:"scan"`
	Result query.ConventionalDNSResponse `json:"result"`
}

func NewDefaultDDRScan(host string, port int, scheduleDoEScans bool) *DDRScan {
	defaultQuery := query.NewDDRQuery()
	defaultQuery.Host = host
	defaultQuery.Port = port

	ddrScan := &DDRScan{
		Meta: DDRScanMetaInformation{
			ScanMetaInformation: ScanMetaInformation{
				Errors: []error{},
			},
			ScheduleDoEScans: scheduleDoEScans,
		},
		Scan: *defaultQuery,
	}

	ddrScan.Meta.GenerateScanID()

	return ddrScan
}
