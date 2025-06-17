package query

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/dchest/uniuri"
	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

// see https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
// however, let's be slightly below the threshold
const MAX_DNS_FQDN_LENGTH = 255
const MAX_SUBDOMAIN_LENGTH = 25
const QUERY_HOST = "f.root-servers.org."

func validateCertificateError(queryErr error, noCertificateErr custom_errors.DoEErrors, res *DoEResponse, skipCertificateVerification bool) custom_errors.DoEErrors {
	setCertificateValidationToResponse(queryErr, res, skipCertificateVerification)
	if queryErr != nil {
		if helper.IsCertificateError(queryErr) {
			cErr := custom_errors.NewCertificateError(queryErr, true).AddInfo(queryErr)
			return cErr
		} else {
			return noCertificateErr.AddInfo(queryErr)
		}
	}

	return nil
}

func setCertificateValidationToResponse(queryErr error, res *DoEResponse, skipCertificateVerification bool) {
	//nolint:gocritic
	if queryErr != nil {
		if helper.IsCertificateError(queryErr) {
			res.CertificateValid = false
			res.CertificateVerified = true
		} else {
			// at this point we cannot say if the certificate is valid or not
			res.CertificateVerified = false
			res.CertificateValid = false
		}
	} else if skipCertificateVerification {
		// since we requested to skip the certificate verification, we cannot say if the certificate is valid or not
		res.CertificateVerified = false
		res.CertificateValid = false
	} else {
		// certificate must be valid
		res.CertificateVerified = true
		res.CertificateValid = true
	}
}

func getAllTLSCipherSuites() []uint16 {
	// Retrieve all cipher suites
	allCipherSuites := tls.CipherSuites()

	// List of all cipher suite IDs
	cipherSuiteIDs := make([]uint16, len(allCipherSuites))
	for i, cs := range allCipherSuites {
		cipherSuiteIDs[i] = cs.ID
	}

	return cipherSuiteIDs
}

func checkForQueryParams(host string, port int, timeout time.Duration, checkForTimeout bool) (err custom_errors.DoEErrors) {
	if host == "" {
		return custom_errors.NewQueryConfigError(custom_errors.ErrHostEmpty, true)
	}

	if port >= 65536 || port <= 0 {
		return custom_errors.NewQueryConfigError(custom_errors.ErrInvalidPort, true).AddInfoString(fmt.Sprintf("port: %d", port))
	}

	if checkForTimeout && timeout < 0 {
		return custom_errors.NewQueryConfigError(custom_errors.ErrInvalidTimeout, true).AddInfoString(fmt.Sprintf("timeout (ms): %d", timeout.Milliseconds()))
	}

	return nil
}

func GetRandomizedQueryHost(host string) string {
	l := MAX_DNS_FQDN_LENGTH - MAX_SUBDOMAIN_LENGTH - len(host)
	if l < 0 {
		return host
	}
	// let's generate some random string to make the FQDN unique
	r := uniuri.NewLen(MAX_SUBDOMAIN_LENGTH)
	return fmt.Sprintf("%s.%s", r, host)
}

func GetDefaultQueryMsg() *dns.Msg {
	msg := &dns.Msg{}

	// let's be cache friendly
	msg.MsgHdr = dns.MsgHdr{
		Id: 0,
	}

	// to analyze recursive-to-authoritative queries, use a
	// query host under your control and set the host
	// to a randomized subdomain of the query host
	// msg.SetQuestion(GetRandomizedQueryHost(QUERY_HOST), dns.TypeA)

	msg.SetQuestion(QUERY_HOST, dns.TypeA)

	return msg
}

func ResolveHost(hostname string, resolver net.IP, qh ConventionalDNSQueryHandlerI) ([]*net.IP, error) {
	ip := net.ParseIP(hostname)

	resolvedIPs := []*net.IP{}

	// ip == nil means we have a hostname to resolve
	if ip == nil {
		// resolve A
		q := NewConventionalQuery()
		q.DNSSEC = false
		q.QueryMsg.SetQuestion(hostname, dns.TypeA)
		q.Host = resolver.String()

		res, err := qh.Query(q)
		if err != nil {
			return nil, err
		}

		if res.Response != nil && res.Response.ResponseMsg != nil {
			for _, rr := range res.Response.ResponseMsg.Answer {
				if a, ok := rr.(*dns.A); ok {
					resolvedIPs = append(resolvedIPs, &a.A)
				}
			}
		}

		// resolve AAAA
		q = NewConventionalQuery()
		q.DNSSEC = false
		q.QueryMsg.SetQuestion(hostname, dns.TypeAAAA)
		q.Host = resolver.String()

		res, err = qh.Query(q)
		if err != nil {
			return nil, err
		}

		if res.Response != nil && res.Response.ResponseMsg != nil {
			for _, rr := range res.Response.ResponseMsg.Answer {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					resolvedIPs = append(resolvedIPs, &aaaa.AAAA)
				}
			}
		}
	} else {
		resolvedIPs = append(resolvedIPs, &ip)
	}

	return resolvedIPs, nil
}
