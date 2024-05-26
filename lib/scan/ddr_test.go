package scan_test

import (
	"net"
	"slices"
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const VALID_QUERY_PATH = "/query{?dns}"
const SAMPLE_TARGET = "example.com"

func TestDDRScan_Constructor(t *testing.T) {
	t.Parallel()
	t.Run("nil query", func(t *testing.T) {
		t.Parallel()

		scan := scan.NewDDRScan(nil, false)

		// test
		assert.Equal(t, "DDR", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.NotEmpty(t, scan.GetScanId(), "should have returned a scan ID")
		assert.Empty(t, scan.GetMetaInformation().ParentScanId, "should be empty")
		assert.Empty(t, scan.GetMetaInformation().RootScanId, "should be empty")
	})

	t.Run("non-nil query", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		scan := scan.NewDDRScan(q, false)

		// test
		assert.Equal(t, "DDR", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, q, scan.Query, "should have attached query")
		assert.NotEmpty(t, scan.GetScanId(), "should have returned a scan ID")
		assert.Empty(t, scan.GetMetaInformation().ParentScanId, "should be empty")
		assert.Empty(t, scan.GetMetaInformation().RootScanId, "should be empty")
	})
}

func TestDDRScan_Marshall(t *testing.T) {
	t.Parallel()
	scan := scan.NewDDRScan(nil, false)
	bytes, err := scan.Marshall()

	// test
	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, bytes, "should have returned bytes")
}

func TestDDRScan_CreateScansFromResponse_EmptyResponse(t *testing.T) {
	t.Parallel()

	t.Run("nil result", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		s.Result = nil

		scans, errors := s.CreateScansFromResponse()

		require.Empty(t, scans, "should have returned no scans")
		require.Nil(t, errors, "should not have returned errors")
	})

	t.Run("nil response", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		s.Result = &query.ConventionalDNSResponse{}

		scans, errors := s.CreateScansFromResponse()

		require.Empty(t, scans, "should have returned no scans")
		require.Nil(t, errors, "should not have returned errors")
	})

	t.Run("nil response DNS msg", func(t *testing.T) {
		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		s.Result = &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: nil,
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.Empty(t, scans, "should have returned no scans")
		require.Nil(t, errors, "should not have returned errors")
	})
}

func TestDDRScan_CreateScansFromResponse_DoH(t *testing.T) {
	t.Parallel()

	// doh
	t.Run("test valid DoH without dohparam and port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 6, len(scans), "should have returned three DoH scans and three certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned SAMPLE_TARGET")
				assert.Equal(t, query.DEFAULT_TLS_PORT, certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned SAMPLE_TARGET")
				assert.Equal(t, query.DEFAULT_DOH_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, query.DEFAULT_DOH_PORT, dohScan.Query.Port, "should have returned default port")
			}
		}
	})

	t.Run("test valid DoH without dohparam but port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
							&dns.SVCBPort{
								Port: port,
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")

		assert.Equal(t, 6, len(scans), "should have returned three DoH scans and three certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOH_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
			}
		}
	})

	t.Run("test valid DoH with dohparam and port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
							&dns.SVCBPort{
								Port: port,
							},
							&dns.SVCBDoHPath{
								Template: VALID_QUERY_PATH,
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")

		assert.Equal(t, 6, len(scans), "should have returned three DoH scans and three certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, "example.com", certScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, VALID_QUERY_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
			}
		}
	})

	t.Run("test valid DoH with dohparam, port and ipv4hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		ipv4HintHost := "8.8.8.8"
		ipv4hint := net.ParseIP(ipv4HintHost)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
							&dns.SVCBPort{
								Port: port,
							},
							&dns.SVCBDoHPath{
								Template: VALID_QUERY_PATH,
							},
							&dns.SVCBIPv4Hint{
								Hint: []net.IP{ipv4hint},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")

		assert.Equal(t, 12, len(scans), "should have returned six DoH scans and six certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				if certScan.Query.Host == ipv4HintHost {
					assert.NotEmpty(t, certScan.Query.SNI, "should not have returned empty SNI")
					certIPConsidered = true
				} else if certScan.Query.Host == SAMPLE_TARGET {
					assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
					certTargetConsidered = true
				}
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, VALID_QUERY_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
				if dohScan.Query.Host == ipv4HintHost {
					doeIpConsidered = true
				} else if dohScan.Query.Host == SAMPLE_TARGET {
					doeTargetConsidered = true
				}
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv4 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv4 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
	})

	t.Run("test valid DoH with dohparam, port and multiple ipv4hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		ipv4hint1 := net.ParseIP("8.8.8.8")
		ipv4hint2 := net.ParseIP("8.8.8.9")
		ipHints := []string{ipv4hint1.String(), ipv4hint2.String()}

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
							&dns.SVCBPort{
								Port: port,
							},
							&dns.SVCBDoHPath{
								Template: VALID_QUERY_PATH,
							},
							&dns.SVCBIPv4Hint{
								Hint: []net.IP{ipv4hint1, ipv4hint2},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 18, len(scans), "should have returned six DoH scans and six certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				if slices.Contains(ipHints, certScan.Query.Host) {
					assert.NotEmpty(t, certScan.Query.SNI, "should not have returned empty SNI")
					certIPConsidered = true
				} else if certScan.Query.Host == SAMPLE_TARGET {
					assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
					certTargetConsidered = true
				}
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)

				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, VALID_QUERY_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")

				if slices.Contains(ipHints, dohScan.Query.Host) {
					doeIpConsidered = true
				} else if dohScan.Query.Host == SAMPLE_TARGET {
					doeTargetConsidered = true
				}
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv6 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv6 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
	})

	t.Run("test valid DoH with dohparam, port and ipv6hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		ipv6hint := net.ParseIP("2001:0db8:85a3:0001:0000:8a2e:0370:7334")

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
							&dns.SVCBPort{
								Port: port,
							},
							&dns.SVCBDoHPath{
								Template: VALID_QUERY_PATH,
							},
							&dns.SVCBIPv6Hint{
								Hint: []net.IP{ipv6hint},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 12, len(scans), "should have returned six DoH scans and six certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				if certScan.Query.Host == ipv6hint.String() {
					assert.NotEmpty(t, certScan.Query.SNI, "should not have returned empty SNI")
					certIPConsidered = true
				} else if certScan.Query.Host == SAMPLE_TARGET {
					assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
					certTargetConsidered = true
				}
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)

				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, VALID_QUERY_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")

				if dohScan.Query.Host == ipv6hint.String() {
					doeIpConsidered = true
				} else if dohScan.Query.Host == SAMPLE_TARGET {
					doeTargetConsidered = true
				}
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv6 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv6 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
	})

	t.Run("test valid DoH with dohparam, port and multiple ipv6hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		ipv6hint1 := net.ParseIP("2001:0db8:85a3:0001:0000:8a2e:0370:7334")
		ipv6hint2 := net.ParseIP("2001:0db8:85a3:0001:0000:8a2e:0370:7335")
		ipHints := []string{ipv6hint1.String(), ipv6hint2.String()}

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"h1", "h2", "h3"},
							},
							&dns.SVCBPort{
								Port: port,
							},
							&dns.SVCBDoHPath{
								Template: VALID_QUERY_PATH,
							},
							&dns.SVCBIPv6Hint{
								Hint: []net.IP{ipv6hint1, ipv6hint2},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 18, len(scans), "should have returned six DoH scans and six certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				if slices.Contains(ipHints, certScan.Query.Host) {
					assert.NotEmpty(t, certScan.Query.SNI, "should not have returned empty SNI")
					certIPConsidered = true
				} else if certScan.Query.Host == SAMPLE_TARGET {
					assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
					certTargetConsidered = true
				}
			} else {
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)

				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, VALID_QUERY_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")

				if slices.Contains(ipHints, dohScan.Query.Host) {
					doeIpConsidered = true
				} else if dohScan.Query.Host == SAMPLE_TARGET {
					doeTargetConsidered = true
				}
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv6 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv6 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
	})
}

func TestDDRScan_CreateScansFromResponse_DoT(t *testing.T) {
	t.Parallel()

	t.Run("test valid DoT without port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"dot"},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 2, len(scans), "should have returned 1 DoH scans and 1 certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOT_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOT_PORT, certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			} else {
				// cast to DoT scan
				dohScan, ok := ss.(*scan.DoTScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOT_PORT, dohScan.Query.Port, "should have returned default port")
			}
		}
	})

	t.Run("test valid DoT with port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"dot"},
							},
							&dns.SVCBPort{
								Port: port,
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 2, len(scans), "should have returned 1 DoH scans and 1 certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOT_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			} else {
				// cast to DoT scan
				dohScan, ok := ss.(*scan.DoTScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
			}
		}
	})
}

func TestDDRScan_CreateScansFromResponse_DoQ(t *testing.T) {
	t.Parallel()

	t.Run("test valid DoQ without port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"doq"},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned errors")
		assert.Equal(t, 2, len(scans), "should have returned 1 DoQ scans and 1 certificate scans (for each requested HTTP ALPN)")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOQ_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOT_PORT, certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			} else {
				// cast to DoT scan
				dohScan, ok := ss.(*scan.DoQScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOQ_PORT, dohScan.Query.Port, "should have returned default port")
			}
		}
	})

	t.Run("test valid DoQ with port", func(t *testing.T) {
		t.Run("test valid DoQ without dohparam and port", func(t *testing.T) {
			t.Parallel()

			q := query.NewDDRQuery()
			s := scan.NewDDRScan(q, false)

			port := uint16(4443)

			s.Result = &query.ConventionalDNSResponse{}
			s.Result.Response = &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
						&dns.SVCB{
							Priority: 1,
							Target:   SAMPLE_TARGET,
							Value: []dns.SVCBKeyValue{
								&dns.SVCBAlpn{
									Alpn: []string{"doq"},
								},
								&dns.SVCBPort{
									Port: port,
								},
							},
						},
					},
				},
			}

			scans, errors := s.CreateScansFromResponse()

			require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
			require.NotNil(t, errors, "should have returned errors")
			assert.Equal(t, 2, len(scans), "should have returned 1 DoQ scans and 1 certificate scans (for each requested HTTP ALPN)")

			for _, err := range errors {
				assert.NotNil(t, err, "should have returned an error")
				assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
			}

			for _, ss := range scans {
				assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOQ_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

				if ss.GetType() == scan.CERTIFICATE_SCAN_TYPE {
					// cast to certificate scan
					certScan, ok := ss.(*scan.CertificateScan)
					require.True(t, ok, "should have returned a certificate scan")

					assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
					assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
					assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
				} else {
					// cast to DoT scan
					dohScan, ok := ss.(*scan.DoQScan)
					require.True(t, ok, "should have returned a DoH scan")

					assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
					assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
				}
			}
		})
	})
}

func TestDDRScan_CreateScansFromResponse_UnkownALPN(t *testing.T) {
	t.Parallel()

	t.Run("unknown ALPN", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false)

		port := uint16(4443)

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							&dns.SVCBAlpn{
								Alpn: []string{"unknown"},
							},
							&dns.SVCBPort{
								Port: port,
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		assert.Equal(t, 0, len(scans), "should not have returned any scans")
		assert.NotNil(t, errors, "should have returned errors")
	})
}
