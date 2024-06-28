package scan

import (
	"encoding/json"
	"fmt"

	"github.com/steffsas/doe-hunter/lib/query"
)

const DNSSEC_SCAN_TYPE = "DNSSEC"

type DNSSECScanMetaInformation struct {
	ScanMetaInformation
}

type DNSSECScan struct {
	Scan

	Meta   *DNSSECScanMetaInformation     `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func (scan *DNSSECScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DNSSECScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *DNSSECScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DNSSECScan) GetType() string {
	return DNSSEC_SCAN_TYPE
}

func (scan *DNSSECScan) GetIdentifier() string {
	// host, port, method, path, http_version, skip_tls_verify
	return fmt.Sprintf("%s|%s",
		DNSSEC_SCAN_TYPE,
		scan.Query.Host,
	)
}

func NewDNSSECScan(targetName, host, protocol, parentScanId, rootScanId, runId, vantagePoint string) *DNSSECScan {
	q := query.NewDNSSECQuery(targetName)
	q.Host = host

	scan := &DNSSECScan{
		Meta: &DNSSECScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Query = q

	return scan
}
