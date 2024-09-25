package consumer_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedConventionalDNSQueryHandler struct {
	mock.Mock
}

func (mqh *mockedConventionalDNSQueryHandler) Query(q *query.ConventionalDNSQuery) (*query.ConventionalDNSResponse, custom_errors.DoEErrors) {
	args := mqh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.ConventionalDNSResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.ConventionalDNSResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestEDSRProcessConsumer_Process(t *testing.T) {
	t.Parallel()

	targetName := "dns.google."

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
		mqh.On("Query", mock.Anything).Return(firstHop, nil)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		edsrScan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Protocol:   "h2",
			TargetName: "dns.google.",
			Host:       "8.8.8.8",
		}

		// marshal to bytes
		edsrScanBytes, _ := json.Marshal(edsrScan)
		msg := &kafka.Message{
			Value: edsrScanBytes,
		}

		// test
		err := pc.Process(msg, msh)

		assert.NoError(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("error"))

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
		mqh.On("Query", mock.Anything).Return(firstHop, nil)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		edsrScan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Protocol:   "h2",
			TargetName: "dns.google.",
			Host:       "8.8.8.8",
		}

		// marshal to bytes
		edsrScanBytes, _ := json.Marshal(edsrScan)
		msg := &kafka.Message{
			Value: edsrScanBytes,
		}

		// test
		err := pc.Process(msg, msh)

		assert.Error(t, err)
	})
}

func TestEDSR_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("valid EDSR scan one.one.one.one", func(t *testing.T) {
		t.Parallel()

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: "one.one.one.one.",
			Host:       "1.1.1.1",
			Result:     &scan.EDSRResult{},
		}

		qh := query.NewEDSRQueryHandler(nil)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: qh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
	})

	t.Run("valid EDSR scan dns.google", func(t *testing.T) {
		t.Parallel()

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: "dns.google.",
			Host:       "8.8.8.8",
			Result:     &scan.EDSRResult{},
		}

		qh := query.NewEDSRQueryHandler(nil)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: qh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
	})

	t.Run("valid EDSR scan adguard", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.adguard-dns.com."

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       "8.8.8.8",
			Result:     &scan.EDSRResult{},
		}

		qh := query.NewEDSRQueryHandler(nil)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: qh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
	})
}

func TestEDSR_StartEDSR(t *testing.T) {
	t.Parallel()

	t.Run("simple mock IPv4 EDSR scan", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "8.8.8.8"

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == host
		})).Return(firstHop, nil)

		// second hop
		secondHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.IP{8, 8, 3, 3},
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == "8.8.4.4"
		})).Return(secondHop, nil)

		// second hop
		thirdHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == "8.8.3.3"
		})).Return(thirdHop, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
		assert.Len(t, scan.Result.Redirections, 3, "should have returned 3 hops")
		assert.True(t, scan.Result.EDSRDetected, "should have detected EDSR")
		assert.Equal(t, scan.Result.Redirections[0].Query.Host, host, fmt.Sprintf("should have queried the first hop with %s", host))
		assert.Equal(t, scan.Result.Redirections[2].Query.Host, "8.8.3.3", "should have queried the last hop with 8.8.3.3")
	})

	t.Run("simple mock IPv6 EDSR scan", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "8.8.8.8"

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1110"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == host
		})).Return(firstHop, nil)

		// second hop
		secondHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1100"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == "2606:4700:4700::1110"
		})).Return(secondHop, nil)

		// third hop
		thirdHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == "2606:4700:4700::1100"
		})).Return(thirdHop, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
		assert.Len(t, scan.Result.Redirections, 3, "should have returned 3 hops")
		assert.True(t, scan.Result.EDSRDetected, "should have detected EDSR")
		assert.Equal(t, scan.Result.Redirections[0].Query.Host, host, fmt.Sprintf("should have queried the first hop with %s", host))
		assert.Equal(t, scan.Result.Redirections[2].Query.Host, "2606:4700:4700::1100", "should have queried the last hop with 2606:4700:4700::1100")
	})

	t.Run("IPv4 and IPv6 glue records", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "8.8.8.8"

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.4.4"),
						},
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1110"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == host
		})).Return(firstHop, nil)

		// second hop
		secondHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.3.3"),
						},
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1100"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "2606:4700:4700::1110" || q.Host == "8.8.4.4")
		})).Return(secondHop, nil)

		// third hop
		thirdHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "2606:4700:4700::1100" || q.Host == "8.8.3.3")
		})).Return(thirdHop, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
		assert.Len(t, scan.Result.Redirections, 5, "should have returned 3 hops")
		assert.True(t, scan.Result.EDSRDetected, "should have detected EDSR")
		assert.Equal(t, scan.Result.Redirections[0].Query.Host, host, fmt.Sprintf("should have queried the first hop with %s", host))

		responses := []*query.ConventionalDNSResponse{
			firstHop,
			secondHop,
			thirdHop,
		}
		// all glue records considered?
		assert.True(t, GlueRecordAsHop(scan.Result.Redirections, responses), "should have considered the glue record")
	})

	t.Run("terminate on loops", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "8.8.8.8"

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.4.4"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == host
		})).Return(firstHop, nil)

		// second hop
		secondHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.3.3"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "8.8.4.4")
		})).Return(secondHop, nil)

		// third hop
		thirdHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.8.8"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "8.8.3.3")
		})).Return(thirdHop, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
		assert.Len(t, scan.Result.Redirections, 3, "should have returned 3 hops")
		assert.True(t, scan.Result.EDSRDetected, "should have detected EDSR")
		assert.Equal(t, scan.Result.Redirections[0].Query.Host, host, fmt.Sprintf("should have queried the first hop with %s", host))

		responses := []*query.ConventionalDNSResponse{
			firstHop,
			secondHop,
			thirdHop,
		}
		// all glue records considered?
		assert.True(t, GlueRecordAsHop(scan.Result.Redirections, responses), "should have considered the glue record")
	})

	t.Run("terminate on loop in one branch", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "8.8.8.8"

		mqh := &mockedConventionalDNSQueryHandler{}

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.4.4"),
						},
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1110"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == host
		})).Return(firstHop, nil)

		// second hop
		secondHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.3.3"),
						},
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1110"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "2606:4700:4700::1110" || q.Host == "8.8.4.4")
		})).Return(secondHop, nil)

		// third hop
		thirdHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "8.8.3.3")
		})).Return(thirdHop, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
		assert.Len(t, scan.Result.Redirections, 4, "should have returned 3 hops")
		assert.True(t, scan.Result.EDSRDetected, "should have detected EDSR")
		assert.Equal(t, scan.Result.Redirections[0].Query.Host, host, fmt.Sprintf("should have queried the first hop with %s", host))

		responses := []*query.ConventionalDNSResponse{
			firstHop,
			secondHop,
			thirdHop,
		}
		// all glue records considered?
		assert.True(t, GlueRecordAsHop(scan.Result.Redirections, responses), "should have considered the glue record")
	})

	t.Run("resolve host if domain is given in first hop", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "dns.google."

		mqh := &mockedConventionalDNSQueryHandler{}

		resolvedResIPv4 := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
						&dns.A{
							Hdr: dns.RR_Header{
								Name:   host,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							A: net.ParseIP("8.8.8.8"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeA &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName)
		})).Return(resolvedResIPv4, nil)

		resolvedResIPv6 := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeAAAA &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName)
		})).Return(resolvedResIPv6, nil)

		// first hop
		firstHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.4.4"),
						},
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1110"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				q.Host == host
		})).Return(firstHop, nil)

		// second hop
		secondHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
							A: net.ParseIP("8.8.3.3"),
						},
						&dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   targetName,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    300,
							},
							AAAA: net.ParseIP("2606:4700:4700::1110"),
						},
					},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "2606:4700:4700::1110" || q.Host == "8.8.4.4")
		})).Return(secondHop, nil)

		// third hop
		thirdHop := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
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
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return q.QueryMsg.Question[0].Qtype == dns.TypeSVCB &&
				strings.Contains(q.QueryMsg.Question[0].Name, targetName) &&
				(q.Host == "8.8.3.3")
		})).Return(thirdHop, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.Empty(t, scan.Meta.Errors, "should not have returned any errors")
		assert.Len(t, scan.Result.Redirections, 4, "should have returned 3 hops")
		assert.True(t, scan.Result.EDSRDetected, "should have detected EDSR")
		assert.Equal(t, scan.Result.Redirections[0].Query.Host, host, fmt.Sprintf("should have queried the first hop with %s", host))

		responses := []*query.ConventionalDNSResponse{
			firstHop,
			secondHop,
			thirdHop,
		}
		// all glue records considered?
		assert.True(t, GlueRecordAsHop(scan.Result.Redirections, responses), "should have considered the glue record")
	})

	t.Run("no ip to hostname results in no hops followed", func(t *testing.T) {
		t.Parallel()

		targetName := "dns.google."
		host := "dns.google."

		mqh := &mockedConventionalDNSQueryHandler{}

		resolvedIPs := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{},
				},
			},
		}
		mqh.On("Query", mock.MatchedBy(func(q *query.ConventionalDNSQuery) bool {
			return (q.QueryMsg.Question[0].Qtype == dns.TypeA || q.QueryMsg.Question[0].Qtype == dns.TypeAAAA)
		})).Return(resolvedIPs, nil)

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: targetName,
			Host:       host,
			Result:     &scan.EDSRResult{},
		}

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		pc.StartEDSR(scan)

		assert.NotEmpty(t, scan.Meta.Errors, "should not have returned an error")
		assert.Len(t, scan.Result.Redirections, 0)
		assert.False(t, scan.Result.EDSRDetected, "should have detected EDSR")
	})

	t.Run("error resolving host should result in no hops", func(t *testing.T) {
		t.Parallel()

		mqh := &mockedConventionalDNSQueryHandler{}
		mqh.On("Query", mock.Anything).Return(nil,
			custom_errors.NewQueryError(errors.New("some error"), true),
		)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		s := &scan.EDSRScan{
			Meta:       &scan.EDSRScanMetaInformation{},
			Host:       "test",
			TargetName: "test",
		}

		pc.StartEDSR(s)

		assert.NotEmpty(t, s.Meta.Errors, "should have returned an error")
	})

	t.Run("error resolving hop", func(t *testing.T) {
		t.Parallel()

		mqh := &mockedConventionalDNSQueryHandler{}
		mqh.On("Query", mock.Anything).Return(nil,
			custom_errors.NewQueryError(errors.New("some error"), true),
		)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: mqh,
		}

		s := &scan.EDSRScan{
			Meta:       &scan.EDSRScanMetaInformation{},
			Host:       "8.8.8.8",
			TargetName: "dns.google.",
			Protocol:   "h2",
			Result:     &scan.EDSRResult{},
		}

		pc.StartEDSR(s)

		assert.NotEmpty(t, s.Meta.Errors, "should have returned an error")
	})
}

func TestEDSR_QueryHop(t *testing.T) {
	t.Parallel()

	t.Run("empty query should return in error", func(t *testing.T) {
		t.Parallel()

		hop := &scan.EDSRHop{
			Query: nil,
		}

		pc := &consumer.EDSRProcessConsumer{}
		nextHops, err := pc.QueryHop(hop, "test", "test", "test", nil)

		assert.Error(t, err)
		assert.Empty(t, nextHops)
		assert.NotEmpty(t, hop.Errors)
	})
}

func TestEDSR_ConnectHops(t *testing.T) {
	t.Parallel()

	t.Run("should connect hops", func(t *testing.T) {
		t.Parallel()

		host := "dns.google."

		hop1 := &scan.EDSRHop{
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "1.1.1.1",
				},
			},
			Id:         "1",
			Hop:        1,
			ChildNodes: []string{},
			GlueRecords: []*scan.GlueRecord{
				{
					IP:   net.ParseIP("2.2.2.2"),
					Host: host,
				},
			},
		}

		hop2 := &scan.EDSRHop{
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "2.2.2.2",
				},
			},
			Id:         "2",
			Hop:        2,
			ChildNodes: []string{},
			GlueRecords: []*scan.GlueRecord{
				{
					IP:   net.ParseIP("3.3.3.3"),
					Host: host,
				},
			},
		}

		hops := []*scan.EDSRHop{
			hop1,
			hop2,
		}

		consumer.ConnectHops(hops)

		assert.Len(t, hop1.ChildNodes, 1)
		assert.Len(t, hop2.ChildNodes, 0)
	})

	t.Run("terminate on loops", func(t *testing.T) {
		t.Parallel()

		host := "dns.google."

		hop1 := &scan.EDSRHop{
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "1.1.1.1",
				},
			},
			Id:         "1",
			Hop:        1,
			ChildNodes: []string{},
			GlueRecords: []*scan.GlueRecord{
				{
					IP:   net.ParseIP("2.2.2.2"),
					Host: host,
				},
				{
					IP:   net.ParseIP("1.1.1.1"),
					Host: host,
				},
			},
		}

		hop2 := &scan.EDSRHop{
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "2.2.2.2",
				},
			},
			Id:         "2",
			Hop:        2,
			ChildNodes: []string{},
			GlueRecords: []*scan.GlueRecord{
				{
					IP:   net.ParseIP("1.1.1.1"),
					Host: host,
				},
			},
		}

		hops := []*scan.EDSRHop{
			hop1,
			hop2,
		}

		consumer.ConnectHops(hops)

		assert.Len(t, hop1.ChildNodes, 2)
		assert.Len(t, hop2.ChildNodes, 1)
	})
}

func TestEDSR_HopContainsChild(t *testing.T) {
	t.Parallel()

	t.Run("should return true if child is in hop", func(t *testing.T) {
		t.Parallel()

		hop := &scan.EDSRHop{
			ChildNodes: []string{"1"},
		}

		assert.True(t, consumer.HopContainsChild(hop, "1"))
	})

	t.Run("should return false if child is not in hop", func(t *testing.T) {
		t.Parallel()

		hop := &scan.EDSRHop{
			ChildNodes: []string{"1"},
		}

		assert.False(t, consumer.HopContainsChild(hop, "2"))
	})
}

func GlueRecordAsHop(hops []*scan.EDSRHop, responses []*query.ConventionalDNSResponse) bool {
	for _, response := range responses {
		if len(response.Response.ResponseMsg.Extra) == 0 {
			continue
		}

		for _, glueRecord := range response.Response.ResponseMsg.Extra {
			if A, ok := glueRecord.(*dns.A); ok {
				considered := false
				for _, hop := range hops {
					if hop.Query.Host == A.A.String() {
						considered = true
						break
					}
				}

				if !considered {
					return false
				}
			}

			if AAAA, ok := glueRecord.(*dns.AAAA); ok {
				considered := false
				for _, hop := range hops {
					if hop.Query.Host == AAAA.AAAA.String() {
						considered = true
						break
					}
				}

				if !considered {
					return false
				}
			}
		}
	}

	return true
}

func TestEDSR_PRocessScan(t *testing.T) {
	t.Parallel()

	t.Run("should return error if scan is nil", func(t *testing.T) {
		t.Parallel()

		pc := &consumer.EDSRProcessConsumer{}

		esh := &storage.EmptyStorageHandler{}

		err := pc.Process(nil, esh)

		assert.Error(t, err)
	})

	t.Run("should return error if scan is not edsrscan", func(t *testing.T) {
		t.Parallel()

		pc := &consumer.EDSRProcessConsumer{}

		esh := &storage.EmptyStorageHandler{}

		msg := &kafka.Message{}

		err := pc.Process(msg, esh)

		assert.Error(t, err)
	})
}
