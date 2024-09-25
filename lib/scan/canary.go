package scan

import (
	"encoding/json"
	"fmt"

	"github.com/steffsas/doe-hunter/lib/query"
)

const CANARY_MOZILLA_DOMAIN = "use-application-dns.net."
const CANARY_APPLE_DOMAIN_MASK = "mask.icloud.com."
const CANARY_APPLE_DOMAIN_MASK_H2 = "mask-h2.icloud.com."

// nolint: gochecknoglobals
var CANARY_DOMAINS = []string{
	CANARY_MOZILLA_DOMAIN,
	// CANARY_APPLE_DOMAIN_MASK,
	// CANARY_APPLE_DOMAIN_MASK_H2,
}

const CANARY_SCAN_TYPE = "canary"

type CanaryScanMetaInformation struct {
	IpVersion string `json:"ip_version"`

	ScanMetaInformation
}

type CanaryScan struct {
	Scan

	Meta   *CanaryScanMetaInformation     `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func (scan *CanaryScan) Marshal() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *CanaryScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *CanaryScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *CanaryScan) GetType() string {
	return CANARY_SCAN_TYPE
}

func (scan *CanaryScan) GetIdentifier() string {
	return fmt.Sprintf("%s|%s|%s|%d",
		CANARY_SCAN_TYPE,
		scan.Query.QueryMsg.Question[0].Name,
		scan.Query.Host,
		scan.Query.Port)
}

func NewCanaryScan(q *query.ConventionalDNSQuery, runId string, vantagePoint string) *CanaryScan {
	if q == nil {
		q = query.NewCanaryQuery("n.a.", "n.a.")
	}

	scan := &CanaryScan{
		Meta: &CanaryScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation("", "", runId, vantagePoint)
	scan.Meta.VantagePoint = vantagePoint
	scan.Query = q
	return scan
}
