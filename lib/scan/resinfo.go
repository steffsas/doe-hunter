package scan

import (
	"encoding/json"
	"fmt"

	"github.com/steffsas/doe-hunter/lib/query"
)

const RESINFO_SCAN_TYPE = "ResInfo"

type ResInfoScanMetaInformation struct {
	ScanMetaInformation
}

type ResInfoResult struct {
	RFC9606Support bool `json:"rfc9606_support"`

	// Indicates whether the resolver has multiple RESINFO records
	MultipleRecords bool `json:"multiple_records"`

	Keys []string `json:"keys"`
}

type ResInfoScan struct {
	Scan

	Meta *ResInfoScanMetaInformation `json:"meta"`

	// The target name to query / the Authentication Domain Name
	TargetName string `json:"target_name"`

	// The host to query
	Host string `json:"host"`

	Result   *ResInfoResult                 `json:"result"`
	Response *query.ConventionalDNSResponse `json:"response"`
}

func (scan *ResInfoScan) Marshal() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *ResInfoScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *ResInfoScan) GetType() string {
	return RESINFO_SCAN_TYPE
}

func (scan *ResInfoScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *ResInfoScan) GetIdentifier() string {
	// host, targetname
	return fmt.Sprintf("%s|%s|%s",
		RESINFO_SCAN_TYPE,
		scan.Host,
		scan.TargetName)
}

func NewResInfoScan(targetName, host, parentScanId, rootScanId, runId, vantagePoint string) *ResInfoScan {
	scan := &ResInfoScan{
		Meta: &ResInfoScanMetaInformation{},
	}

	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)

	scan.Host = host
	scan.TargetName = targetName
	return scan
}
