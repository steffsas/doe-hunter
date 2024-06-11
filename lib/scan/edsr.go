package scan

import (
	"encoding/json"
	"net"

	"github.com/google/uuid"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/svcb"
)

type EDSRScanMetaInformation struct {
	ScanMetaInformation
}

type EDSRResult struct {
	// true if there is at least one valid EDSR redirection (including to the host itself)
	EDSRDetected bool `json:"edsr_detected"`
	// true if there is a loop of redirections
	Loop bool `json:"loop"`

	Redirections []*EDSRHop `json:"hops"`
}

type EDSRHop struct {
	Id             string                         `json:"id"`
	ParentId       string                         `json:"parent_id"`
	Hop            int                            `json:"hop"`
	Errors         []custom_errors.DoEErrors      `json:"errors"`
	Query          *query.ConventionalDNSQuery    `json:"query"`
	Result         *query.ConventionalDNSResponse `json:"result"`
	ConsideredSVCB *svcb.SVCBRR                   `json:"considered_svcb"`
	GlueRecords    []*net.IP                      `json:"glue_records"`
}

func NewEDSRHop(parentId string, parentHop int, query *query.ConventionalDNSQuery) *EDSRHop {
	return &EDSRHop{
		Id:          uuid.New().String(),
		ParentId:    parentId,
		Hop:         parentHop + 1,
		Query:       query,
		GlueRecords: make([]*net.IP, 0),
	}
}

// see https://www.ietf.org/id/draft-jt-add-dns-server-redirection-04.html
type EDSRScan struct {
	Scan

	Meta *EDSRScanMetaInformation `json:"meta"`

	// the protocol to scan for, e.g., h2, h3, dot, doq, etc.
	Protocol string `json:"protocol"`

	// the targetName to scan for in SVCB records (see strict origin redirection in the draft)
	TargetName string `json:"target_name"`

	// the initial query to start from
	Query  *query.ConventionalDNSQuery `json:"query"`
	Result *EDSRResult                 `json:"result"`
}

func (scan *EDSRScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *EDSRScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *EDSRScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *EDSRScan) GetType() string {
	return DDR_SCAN_TYPE
}

func NewEDSRScan(initialQuery *query.ConventionalDNSQuery, protocol, parentScanId, rootScanId, runId, vantagePoint string) *EDSRScan {
	scan := &EDSRScan{
		Meta: &EDSRScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Protocol = protocol
	scan.Query = initialQuery
	return scan
}
