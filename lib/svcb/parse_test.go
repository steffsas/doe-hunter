package svcb_test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/svcb"
	"github.com/stretchr/testify/assert"
)

func TestParseDDRSVCB(t *testing.T) {
	t.Parallel()

	t.Run("ALPN", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should not be nil")
		assert.Empty(t, errs, "errs should be empty")
		assert.Equal(t, "example.com", svcbRR.Target)
		assert.Equal(t, "h3", svcbRR.Alpn.Alpn[0])
	})

	t.Run("Port", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
				&dns.SVCBPort{
					Port: 443,
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should not be nil")
		assert.Empty(t, errs, "errs should be empty")
		assert.Equal(t, "example.com", svcbRR.Target)
		assert.Equal(t, "h3", svcbRR.Alpn.Alpn[0])
		assert.Equal(t, uint16(443), svcbRR.Port.Port)
	})

	t.Run("IPv4Hint", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
				&dns.SVCBPort{
					Port: 443,
				},
				&dns.SVCBIPv4Hint{
					Hint: []net.IP{net.ParseIP("8.8.8.8")},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should not be nil")
		assert.Empty(t, errs, "errs should be empty")
		assert.Equal(t, "example.com", svcbRR.Target)
		assert.Equal(t, "h3", svcbRR.Alpn.Alpn[0])
		assert.Equal(t, uint16(443), svcbRR.Port.Port)
		assert.Equal(t, "8.8.8.8", svcbRR.IPv4Hint.Hint[0].String())
	})

	t.Run("IPv6Hint", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
				&dns.SVCBPort{
					Port: 443,
				},
				&dns.SVCBIPv6Hint{
					Hint: []net.IP{net.ParseIP("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should not be nil")
		assert.Empty(t, errs, "errs should be empty")
		assert.Equal(t, "example.com", svcbRR.Target)
		assert.Equal(t, "h3", svcbRR.Alpn.Alpn[0])
		assert.Equal(t, uint16(443), svcbRR.Port.Port)
		assert.Equal(t, "2001:db8:85a3:8d3:1319:8a2e:370:7344", svcbRR.IPv6Hint.Hint[0].String())
	})

	t.Run("DoHPath", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
				&dns.SVCBPort{
					Port: 443,
				},
				&dns.SVCBDoHPath{
					Template: "/dns-query",
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should not be nil")
		assert.Empty(t, errs, "errs should be empty")
		assert.Equal(t, "example.com", svcbRR.Target)
		assert.Equal(t, "h3", svcbRR.Alpn.Alpn[0])
		assert.Equal(t, uint16(443), svcbRR.Port.Port)
		assert.Equal(t, "/dns-query", svcbRR.DoHPath.Template)
	})

	t.Run("ODoH", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
				&dns.SVCBPort{
					Port: 443,
				},
				&dns.SVCBDoHPath{
					Template: "/dns-query",
				},
				// odoh key code
				&dns.SVCBLocal{
					KeyCode: 0x08,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should not be nil")
		assert.Empty(t, errs, "errs should be empty")
		assert.Equal(t, "example.com", svcbRR.Target)
		assert.Equal(t, "h3", svcbRR.Alpn.Alpn[0])
		assert.Equal(t, uint16(443), svcbRR.Port.Port)
		assert.Equal(t, "/dns-query", svcbRR.DoHPath.Template)
		assert.True(t, svcbRR.ODoH)
	})

	t.Run("Invalid ALPN", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("Invalid target", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("Invalid ALPN cast", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBLocal{
					KeyCode: 0x01,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("Invalid port cast", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBLocal{
					KeyCode: 0x03,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("Invalid ipv4hint cast", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBLocal{
					KeyCode: 0x04,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("Invalid ipv6hint cast", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBLocal{
					KeyCode: 0x06,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("Invalid dohpath cast", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBLocal{
					KeyCode: 0x07,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.Nil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")
	})

	t.Run("unknown svcb key", func(t *testing.T) {
		t.Parallel()

		s := &dns.SVCB{
			Priority: 1,
			Target:   "example.com",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBAlpn{
					Alpn: []string{"h3"},
				},
				&dns.SVCBLocal{
					KeyCode: 0x10,
					Data:    []byte{},
				},
			},
		}

		svcbRR, errs := svcb.ParseDDRSVCB("scanId", s)

		assert.NotNil(t, svcbRR, "svcbRR should be nil")
		assert.NotEmpty(t, errs, "errs should not be empty")

		for _, err := range errs {
			assert.False(t, err.IsCritical(), "error should not be critical")
		}
	})
}
