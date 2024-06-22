package scan

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/svcb"
)

const EDSR_SCAN_TYPE = "EDSR"

type EDSRScanMetaInformation struct {
	ScanMetaInformation
}

type EDSRResult struct {
	// true if there is at least one valid EDSR redirection (including to the host itself)
	EDSRDetected bool `json:"edsr_detected"`

	Redirections []*EDSRHop `json:"hops"`
}

type GlueRecord struct {
	IP   net.IP `json:"ip"`
	Host string `json:"host"`
}

type EDSRHop struct {
	Id             string                         `json:"id"`
	ChildNodes     []string                       `json:"child_nodes"`
	Hop            int                            `json:"hop"`
	Errors         []custom_errors.DoEErrors      `json:"errors"`
	Query          *query.ConventionalDNSQuery    `json:"query"`
	Result         *query.ConventionalDNSResponse `json:"result"`
	ConsideredSVCB *svcb.SVCBRR                   `json:"considered_svcb"`
	GlueRecords    []*GlueRecord                  `json:"glue_records"`
}

func NewEDSRHop(parentHop int, query *query.ConventionalDNSQuery) *EDSRHop {
	return &EDSRHop{
		Id:          uuid.New().String(),
		ChildNodes:  []string{},
		Hop:         parentHop + 1,
		Query:       query,
		GlueRecords: []*GlueRecord{},
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

	// the host to start the EDSR scan from
	Host string `json:"host"`

	Result *EDSRResult `json:"result"`
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
	return EDSR_SCAN_TYPE
}

func (scan *EDSRScan) GetIdentifier() string {
	// host, port
	return fmt.Sprintf("%s|%s|%s",
		EDSR_SCAN_TYPE,
		scan.Host,
		scan.TargetName)
}

func NewEDSRScan(targetName, host, protocol, parentScanId, rootScanId, runId, vantagePoint string) *EDSRScan {
	scan := &EDSRScan{
		Meta: &EDSRScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(parentScanId, rootScanId, runId, vantagePoint)
	scan.Protocol = protocol
	scan.Host = host
	scan.TargetName = targetName
	return scan
}

func CheckForDoEProtocol(scanId string, targetName string, protocol string, res *query.ConventionalDNSResponse) (svcbRR *svcb.SVCBRR, errColl []custom_errors.DoEErrors) {
	if (res == nil) || (res.Response == nil) || (res.Response.ResponseMsg == nil) {
		return nil, append(errColl, custom_errors.NewQueryError(custom_errors.ErrNoResponse, true).AddInfoString("response is empty"))
	}

	for _, answer := range res.Response.ResponseMsg.Answer {
		svcbRecord, ok := answer.(*dns.SVCB)
		if !ok {
			errColl = append(errColl, custom_errors.NewQueryError(custom_errors.ErrInvalidSVCBRR, false).AddInfoString("could not cast DNS answer to SVCB"))
			continue
		}

		// see https://www.ietf.org/id/draft-jt-add-dns-server-redirection-04.html, strict origin redirection
		if svcbRecord.Target != targetName {
			continue
		}

		// parse SVCB record
		svcbEntry, err := svcb.ParseDDRSVCB(scanId, svcbRecord)
		errColl = append(errColl, err...)
		if custom_errors.ContainsCriticalErr(err) {
			logrus.Errorf("parsing EDSR scan %s: critical error while parsing SVCB record, ignore DNS RR", scanId)
			continue
		}

		for _, alpn := range svcbEntry.Alpn.Alpn {
			if alpn == protocol {
				// we found an SVCB record to the same protocol with a lower priority than the current one
				return svcbEntry, errColl
			}
		}
	}

	// return critical error since we did not find a record with the requested protocol
	return nil, append(errColl,
		custom_errors.NewQueryError(custom_errors.ErrResolverDoesNotAdvertiseProtocol, true).
			AddInfoString(fmt.Sprintf("resolver does not advertise protocol %s", protocol)))
}
