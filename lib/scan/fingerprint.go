package scan

import (
	"encoding/json"
	"fmt"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
)

const FINGERPRINT_SCAN_TYPE = "fingerprint"

type FingerprintScanMetaInformation struct {
	ScanMetaInformation
}

type FingerprintScan struct {
	Scan

	Meta *FingerprintScanMetaInformation `json:"meta"`

	VersionBindQuery   *query.ConventionalDNSQuery `json:"version_bind_query"`
	VersionServerQuery *query.ConventionalDNSQuery `json:"version_server_query"`
	SSHQuery           *query.SSHQuery             `json:"ssh_query"`

	VersionBindResult   *query.ConventionalDNSResponse `json:"version_bind_result"`
	VersionServerResult *query.ConventionalDNSResponse `json:"version_server_result"`
	SSHResult           *query.SSHResponse             `json:"ssh_result"`
}

func (scan *FingerprintScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *FingerprintScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *FingerprintScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *FingerprintScan) GetType() string {
	return FINGERPRINT_SCAN_TYPE
}

func (scan *FingerprintScan) GetIdentifier() string {
	// host, port, protocol, alpn
	// tls_skip_verify is not part of the identifier because we will get the certificate in a second query if certificate is not valid
	return fmt.Sprintf("%s|%s",
		FINGERPRINT_SCAN_TYPE,
		scan.SSHQuery.Host,
	)
}

func NewFingerprintScan(host string, rootScanId, parentScanId, runId, vantagePoint string) *FingerprintScan {
	scan := &FingerprintScan{
		Meta: &FingerprintScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation(rootScanId, parentScanId, runId, vantagePoint)

	versionBind := query.NewConventionalQuery()
	versionBind.Host = host

	// version.bind is a special query that is used to determine the version of the DNS server
	// https://tools.ietf.org/html/rfc4892
	versionBindQuestion := dns.Question{
		Name:   "version.bind.",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassCHAOS,
	}
	versionBind.DNSQuery.QueryMsg = new(dns.Msg)
	versionBind.DNSQuery.QueryMsg.Question = make([]dns.Question, 1)
	versionBind.DNSQuery.QueryMsg.Question[0] = versionBindQuestion
	versionBind.DNSQuery.QueryMsg.Id = 0
	versionBind.DNSQuery.QueryMsg.RecursionDesired = true
	scan.VersionBindQuery = versionBind

	versionServer := query.NewConventionalQuery()
	versionServer.Host = host

	// version.server is a special query that is used to determine the version of the DNS server
	versionServerQuestion := dns.Question{
		Name:   "version.server.",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassCHAOS,
	}
	versionServer.DNSQuery.QueryMsg = new(dns.Msg)
	versionServer.DNSQuery.QueryMsg.Question = make([]dns.Question, 1)
	versionServer.DNSQuery.QueryMsg.Question[0] = versionServerQuestion
	versionServer.DNSQuery.QueryMsg.Id = 0
	versionServer.DNSQuery.QueryMsg.RecursionDesired = true

	scan.VersionServerQuery = versionServer

	sshQuery := query.NewSSHQuery(host)
	scan.SSHQuery = sshQuery

	return scan
}
