package scan_test

import (
	"encoding/json"
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

		scan := scan.NewDDRScan(nil, false, "test", "runid")

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
		scan := scan.NewDDRScan(q, false, "test", "runid")

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

	t.Run("marshal DDR scan", func(t *testing.T) {
		t.Parallel()
		scan := scan.NewDDRScan(nil, false, "test", "runid")
		bytes, err := scan.Marshal()

		// test
		assert.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, bytes, "should have returned bytes")
	})

	t.Run("marshal DoH scan created by DDR discovery", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

		s.Result = &query.ConventionalDNSResponse{}
		s.Result.Response = &query.DNSResponse{
			ResponseMsg: &dns.Msg{
				Answer: []dns.RR{
					&dns.SVCB{
						Priority: 1,
						Target:   SAMPLE_TARGET,
						Value: []dns.SVCBKeyValue{
							// no DoH path given
							&dns.SVCBAlpn{
								Alpn: []string{"h2"},
							},
						},
					},
				},
			},
		}

		scans, errors := s.CreateScansFromResponse()

		require.GreaterOrEqual(t, len(scans), 1, "should have returned at least one scan")
		require.NotNil(t, errors, "should have returned the missing dohpath error")

		// marshal
		var dohScan *scan.DoHScan
		for _, s := range scans {
			if s.GetType() == scan.DOH_SCAN_TYPE {
				dohScan = s.(*scan.DoHScan)
				break
			}
		}
		require.NotNil(t, dohScan, "should have returned a DoH scan")

		// marshal
		b, err := dohScan.Marshal()

		require.Nil(t, err, "should not have returned an error")
		assert.NotNil(t, b, "should have returned bytes")

		// unmarshall
		dohScan = &scan.DoHScan{}
		err = json.Unmarshal(b, dohScan)
		require.Nil(t, err, "should not have returned an error")
	})
}

func TestDDRScan_CreateScansFromResponse_EmptyResponse(t *testing.T) {
	t.Parallel()

	t.Run("nil result", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

		s.Result = nil

		scans, errors := s.CreateScansFromResponse()

		require.Empty(t, scans, "should have returned no scans")
		require.Nil(t, errors, "should not have returned errors")
	})

	t.Run("nil response", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

		s.Result = &query.ConventionalDNSResponse{}

		scans, errors := s.CreateScansFromResponse()

		require.Empty(t, scans, "should have returned no scans")
		require.Nil(t, errors, "should not have returned errors")
	})

	t.Run("nil response DNS msg", func(t *testing.T) {
		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 3, c[scan.DOH_SCAN_TYPE])
		assert.Equal(t, 3, c[scan.CERTIFICATE_SCAN_TYPE])
		assert.Equal(t, 3, c[scan.EDSR_SCAN_TYPE])
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE])

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned SAMPLE_TARGET")
				assert.Equal(t, query.DEFAULT_TLS_PORT, certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			case scan.DOH_SCAN_TYPE:
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned SAMPLE_TARGET")
				assert.Equal(t, query.DEFAULT_DOH_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, query.DEFAULT_DOH_PORT, dohScan.Query.Port, "should have returned default port")
			case scan.EDSR_SCAN_TYPE:
				// cast to DoH scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
				assert.Equal(t, SAMPLE_TARGET, edsrScan.Host, "should have returned SAMPLE_TARGET as host")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				assert.Equal(t, SAMPLE_TARGET, dnssecScan.Query.Host)
				assert.Equal(t, SAMPLE_TARGET, dnssecScan.Meta.OriginTargetName)
			}
		}
	})

	t.Run("test valid DoH without dohparam but port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 3, c[scan.DOH_SCAN_TYPE])
		assert.Equal(t, 3, c[scan.CERTIFICATE_SCAN_TYPE])
		assert.Equal(t, 3, c[scan.EDSR_SCAN_TYPE])
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE])

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			case scan.DOH_SCAN_TYPE:
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOH_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
			case scan.EDSR_SCAN_TYPE:
				// cast to DoH scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
				assert.Equal(t, SAMPLE_TARGET, edsrScan.Host, "should have returned SAMPLE_TARGET as host")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				assert.Equal(t, SAMPLE_TARGET, dnssecScan.Query.Host)
				assert.Equal(t, SAMPLE_TARGET, dnssecScan.Meta.OriginTargetName)
			}
		}
	})

	t.Run("test valid DoH with dohparam and port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 3, c[scan.DOH_SCAN_TYPE])
		assert.Equal(t, 3, c[scan.CERTIFICATE_SCAN_TYPE])
		assert.Equal(t, 3, c[scan.EDSR_SCAN_TYPE])
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE])

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, "example.com", certScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			case scan.DOH_SCAN_TYPE:
				// cast to DoH scan
				dohScan, ok := ss.(*scan.DoHScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dohScan.Query.Host, "should have returned target")
				assert.Equal(t, VALID_QUERY_PATH, dohScan.Query.URI, "should have returned default template URI")
				assert.Equal(t, int(port), dohScan.Query.Port, "should have returned default port")
			case scan.EDSR_SCAN_TYPE:
				// cast to DoH scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
				assert.Equal(t, SAMPLE_TARGET, edsrScan.Host, "should have returned SAMPLE_TARGET as host")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				assert.Equal(t, SAMPLE_TARGET, dnssecScan.Query.Host)
				assert.Equal(t, SAMPLE_TARGET, dnssecScan.Meta.OriginTargetName)
			}
		}
	})

	t.Run("test valid DoH with dohparam, port and ipv4hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 6, c[scan.DOH_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 6, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 6, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 2, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		dnssecConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
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
			case scan.DOH_SCAN_TYPE:
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
			case scan.EDSR_SCAN_TYPE:
				// cast to DoH scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				edsrConsidered := false
				if edsrScan.Host == ipv4HintHost {
					assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
					edsrConsidered = true
				} else if edsrScan.Host == SAMPLE_TARGET {
					assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
					edsrConsidered = true
				}

				assert.True(t, edsrConsidered, "should have considered target for edsr")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				dnssecConsidered = true

				assert.Contains(t, []string{ipv4HintHost, SAMPLE_TARGET}, dnssecScan.Query.Host)
				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv4 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv4 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
		assert.True(t, dnssecConsidered, "should have considered target for dnssec")
	})

	t.Run("test valid DoH with dohparam, port and multiple ipv4hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 9, c[scan.DOH_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 9, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 9, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 3, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			require.Nil(t, err, "should not have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		dnssecConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
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
			case scan.DOH_SCAN_TYPE:
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
			case scan.EDSR_SCAN_TYPE:
				// cast to EDSR scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				edsrConsidered := false
				if slices.Contains(ipHints, edsrScan.Host) {
					assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
					edsrConsidered = true
				} else if edsrScan.Host == SAMPLE_TARGET {
					assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
					edsrConsidered = true
				}

				assert.True(t, edsrConsidered, "should have considered target for edsr")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				dnssecConsidered = false

				if slices.Contains(ipHints, dnssecScan.Query.Host) {
					dnssecConsidered = true
				} else if dnssecScan.Query.Host == SAMPLE_TARGET {
					dnssecConsidered = true
				}
				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv6 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv6 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
		assert.True(t, dnssecConsidered, "should have considered dnssec")
	})

	t.Run("test valid DoH with dohparam, port and ipv6hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 6, c[scan.DOH_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 6, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 6, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 2, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		dnssecConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
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
			case scan.DOH_SCAN_TYPE:
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
			case scan.EDSR_SCAN_TYPE:
				// cast to EDSR scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				edsrConsidered := false
				if edsrScan.Host == ipv6hint.String() {
					edsrConsidered = true
				} else if edsrScan.Host == SAMPLE_TARGET {
					edsrConsidered = true
				}

				assert.True(t, edsrConsidered, "should have considered target for edsr")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				dnssecConsidered = false

				if ipv6hint.String() == dnssecScan.Query.Host {
					dnssecConsidered = true
				} else if dnssecScan.Query.Host == SAMPLE_TARGET {
					dnssecConsidered = true
				}
				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv6 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv6 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
		assert.True(t, dnssecConsidered, "should have considered DNSSEC")
	})

	t.Run("test valid DoH with dohparam, port and multiple ipv6hint", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 9, c[scan.DOH_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 9, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 9, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 3, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			require.Nil(t, err, "should have returned an error")
		}

		doeIpConsidered := false
		doeTargetConsidered := false

		certIPConsidered := false
		certTargetConsidered := false

		dnssecConsidered := false

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOH_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
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
			case scan.DOH_SCAN_TYPE:
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
			case scan.EDSR_SCAN_TYPE:
				// cast to EDSR scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				edsrConsidered := false
				if slices.Contains(ipHints, edsrScan.Host) {
					edsrConsidered = true
				} else if edsrScan.Host == SAMPLE_TARGET {
					edsrConsidered = true
				}

				assert.True(t, edsrConsidered, "should have considered target for edsr")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				dnssecConsidered = false

				if slices.Contains(ipHints, dnssecScan.Query.Host) {
					dnssecConsidered = true
				} else if dnssecScan.Query.Host == SAMPLE_TARGET {
					dnssecConsidered = true
				}
				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}

		assert.True(t, doeIpConsidered, "should have considered ipv6 hint for doe")
		assert.True(t, doeTargetConsidered, "should have considered target for doe")
		assert.True(t, certIPConsidered, "should have considered ipv6 hint for cert")
		assert.True(t, certTargetConsidered, "should have considered target for cert")
		assert.True(t, dnssecConsidered, "should have considered dnssec")
	})
}

func TestDDRScan_CreateScansFromResponse_DoT(t *testing.T) {
	t.Parallel()

	t.Run("test valid DoT without port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 1, c[scan.DOT_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOT_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOT_PORT, certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			case scan.DOT_SCAN_TYPE:
				// cast to DoT scan
				dotScan, ok := ss.(*scan.DoTScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dotScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOT_PORT, dotScan.Query.Port, "should have returned default port")
			case scan.EDSR_SCAN_TYPE:
				// cast to EDSR scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}
	})

	t.Run("test valid DoT with port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 1, c[scan.DOT_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOT_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			case scan.DOT_SCAN_TYPE:
				// cast to DoT scan
				dotScan, ok := ss.(*scan.DoTScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, dotScan.Query.Host, "should have returned target")
				assert.Equal(t, int(port), dotScan.Query.Port, "should have returned default port")
			case scan.EDSR_SCAN_TYPE:
				// cast to EDSR scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}
	})
}

func TestDDRScan_CreateScansFromResponse_DoQ(t *testing.T) {
	t.Parallel()

	t.Run("test valid DoQ without port", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		c := scanCounter(scans)
		assert.Equal(t, 1, c[scan.DOQ_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		for _, err := range errors {
			assert.NotNil(t, err, "should have returned an error")
			assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
		}

		for _, ss := range scans {
			assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOQ_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

			switch ss.GetType() {
			case scan.CERTIFICATE_SCAN_TYPE:
				// cast to certificate scan
				certScan, ok := ss.(*scan.CertificateScan)
				require.True(t, ok, "should have returned a certificate scan")

				assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOT_PORT, certScan.Query.Port, "should have returned default port")
				assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
			case scan.DOQ_SCAN_TYPE:
				// cast to DoT scan
				doqScan, ok := ss.(*scan.DoQScan)
				require.True(t, ok, "should have returned a DoH scan")

				assert.Equal(t, SAMPLE_TARGET, doqScan.Query.Host, "should have returned target")
				assert.Equal(t, query.DEFAULT_DOQ_PORT, doqScan.Query.Port, "should have returned default port")
			case scan.EDSR_SCAN_TYPE:
				// cast to EDSR scan
				edsrScan, ok := ss.(*scan.EDSRScan)
				require.True(t, ok, "should have returned an EDSR scan")

				assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
			case scan.DDR_DNSSEC_SCAN_TYPE:
				// cast to DNSSEC scan
				dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
				require.True(t, ok, "should have returned an DNSSEC scan")

				assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
			}
		}
	})

	t.Run("test valid DoQ with port", func(t *testing.T) {
		t.Run("test valid DoQ without dohparam and port", func(t *testing.T) {
			t.Parallel()

			q := query.NewDDRQuery()
			s := scan.NewDDRScan(q, false, "test", "runid")

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

			c := scanCounter(scans)
			assert.Equal(t, 1, c[scan.DOQ_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
			assert.Equal(t, 1, c[scan.CERTIFICATE_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
			assert.Equal(t, 1, c[scan.EDSR_SCAN_TYPE], "ALPN * (ipv4Hint + targetName)")
			assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

			for _, err := range errors {
				assert.NotNil(t, err, "should have returned an error")
				assert.False(t, err.IsCritical(), "should not have returned a critical error, we expect default template URI")
			}

			for _, ss := range scans {
				assert.Contains(t, []string{scan.CERTIFICATE_SCAN_TYPE, scan.DOQ_SCAN_TYPE, scan.EDSR_SCAN_TYPE, scan.DDR_DNSSEC_SCAN_TYPE}, ss.GetType(), "should have returned DoH or certificate scan types")

				switch ss.GetType() {
				case scan.CERTIFICATE_SCAN_TYPE:
					// cast to certificate scan
					certScan, ok := ss.(*scan.CertificateScan)
					require.True(t, ok, "should have returned a certificate scan")

					assert.Equal(t, SAMPLE_TARGET, certScan.Query.Host, "should have returned target")
					assert.Equal(t, int(port), certScan.Query.Port, "should have returned default port")
					assert.Empty(t, certScan.Query.SNI, "should have returned empty SNI")
				case scan.DOQ_SCAN_TYPE:
					// cast to DoT scan
					doqScan, ok := ss.(*scan.DoQScan)
					require.True(t, ok, "should have returned a DoH scan")

					assert.Equal(t, SAMPLE_TARGET, doqScan.Query.Host, "should have returned target")
					assert.Equal(t, int(port), doqScan.Query.Port, "should have returned default port")
				case scan.EDSR_SCAN_TYPE:
					// cast to EDSR scan
					edsrScan, ok := ss.(*scan.EDSRScan)
					require.True(t, ok, "should have returned an EDSR scan")

					assert.Equal(t, SAMPLE_TARGET, edsrScan.TargetName, "should have returned SAMPLE_TARGET as targetName")
				case scan.DDR_DNSSEC_SCAN_TYPE:
					// cast to DNSSEC scan
					dnssecScan, ok := ss.(*scan.DDRDNSSECScan)
					require.True(t, ok, "should have returned an DNSSEC scan")

					assert.Equal(t, dnssecScan.Meta.OriginTargetName, SAMPLE_TARGET)
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
		s := scan.NewDDRScan(q, false, "test", "runid")

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

		assert.Equal(t, 1, len(scans))

		c := scanCounter(scans)
		assert.Equal(t, 1, c[scan.DDR_DNSSEC_SCAN_TYPE], "targetName + ipv4Hint")

		assert.NotNil(t, errors, "should have returned errors")
	})
}

func scanCounter(sc []scan.Scan) map[string]int {
	sM := make(map[string]int)
	for _, s := range sc {
		sM[s.GetType()] += 1
	}

	return sM
}
