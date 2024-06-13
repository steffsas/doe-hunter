package scan_test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEDSR_CheckForDoEProtocol(t *testing.T) {
	t.Parallel()

	t.Run("should return true if DoE is detected", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."

		selectedTarget := &dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   targetName,
				Rrtype: dns.TypeSVCB,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Priority: 1,
			Target:   targetName,
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h2"},
				},
			},
		}

		res := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
						&dns.SVCB{
							Hdr: dns.RR_Header{
								Name:   "some other target",
								Rrtype: dns.TypeSVCB,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Priority: 1,
							Target:   "some other target",
							Value: []dns.SVCBKeyValue{
								&dns.SVCBAlpn{
									Alpn: []string{"h3"},
								},
							},
						},
						selectedTarget,
					},
					Extra: []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.IP{8, 8, 4, 4},
						},
					},
				},
			},
		}

		rr, err := scan.CheckForDoEProtocol("scanId", targetName, "h2", res)

		assert.Empty(t, err)
		assert.NotNil(t, rr)
		assert.Equal(t, selectedTarget.Target, rr.Target)
	})

	t.Run("should return error if res is nil", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."

		rr, err := scan.CheckForDoEProtocol("scanId", targetName, "h2", nil)

		assert.NotEmpty(t, err)
		assert.Nil(t, rr)
	})

	t.Run("should return error if res is nil", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."

		rr, err := scan.CheckForDoEProtocol("scanId", targetName, "h2", nil)

		assert.NotEmpty(t, err)
		assert.Nil(t, rr)
	})

	t.Run("should ignore invalid SVCBs", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."

		res := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.IPv4(8, 8, 8, 8),
						},
						&dns.SVCB{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeSVCB,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							Priority: 1,
							Target:   targetName,
							Value: []dns.SVCBKeyValue{
								&dns.SVCBAlpn{
									Alpn: []string{"h2"},
								},
							},
						},
					},
					Extra: []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.IP{8, 8, 4, 4},
						},
					},
				},
			},
		}

		rr, err := scan.CheckForDoEProtocol("scanId", targetName, "h2", res)

		assert.NotEmpty(t, err)
		require.NotNil(t, rr)
		assert.Equal(t, targetName, rr.Target)
	})

	t.Run("no SVCBs", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."

		res := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{},
					Extra:  []dns.RR{},
				},
			},
		}

		rr, err := scan.CheckForDoEProtocol("scanId", targetName, "h2", res)

		assert.NotEmpty(t, err)
		assert.Nil(t, rr)
	})
}

func TestEDSR_NewEDSRScan(t *testing.T) {
	t.Parallel()

	t.Run("should create a new EDSR scan", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "8.8.8.8"
		protocol := "h2"

		scan := scan.NewEDSRScan(targetName, host, protocol, "parentScanId", "rootScanId", "runId", "vantagePoint")

		assert.Equal(t, protocol, scan.Protocol)
		assert.Equal(t, host, scan.Host)
		assert.Equal(t, targetName, scan.TargetName)
	})
}

func TestEDSR_NewEDSRHop(t *testing.T) {
	t.Parallel()

	t.Run("should create a new EDSR hop", func(t *testing.T) {
		t.Parallel()

		parentHop := 1
		q := query.NewConventionalQuery()

		edsrHop := scan.NewEDSRHop(parentHop, q)

		assert.Equal(t, parentHop+1, edsrHop.Hop)
		assert.Equal(t, q, edsrHop.Query)
	})

}
