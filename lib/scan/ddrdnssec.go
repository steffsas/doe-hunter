package scan

import (
	"encoding/json"
	"fmt"

	"github.com/steffsas/doe-hunter/lib/query"
)

const DDR_DNSSEC_SCAN_TYPE = "DDR_DNSSEC"

type DDRDNSSECScanMetaInformation struct {
	ScanMetaInformation

	OriginTargetName string
}

type DDRDNSSECScan struct {
	Scan

	Meta   *DDRDNSSECScanMetaInformation  `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func (scan *DDRDNSSECScan) Marshal() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DDRDNSSECScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *DDRDNSSECScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DDRDNSSECScan) GetType() string {
	return DDR_DNSSEC_SCAN_TYPE
}

func (scan *DDRDNSSECScan) GetIdentifier() string {
	// host, port, method, path, http_version, skip_tls_verify
	return fmt.Sprintf("%s|%s|%s",
		DDR_DNSSEC_SCAN_TYPE,
		scan.Meta.OriginTargetName,
		scan.Query.Host,
	)
}

func NewDDRDNSSECScan(targetName, host, parentScanId, rootScanId, runId, vantagePoint string) *DDRDNSSECScan {
	q := query.NewDDRDNSSECQuery(targetName)
	q.Host = host

	scan := &DDRDNSSECScan{
		Meta: &DDRDNSSECScanMetaInformation{
			OriginTargetName: targetName,
		},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Query = q

	return scan
}
