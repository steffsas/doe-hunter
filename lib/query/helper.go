package query

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

func ParseIPAddresses(res *ConventionalDNSResponse) []*net.IP {
	ips := []*net.IP{}

	if res != nil && res.Response != nil && res.Response.ResponseMsg != nil {
		for _, rr := range res.Response.ResponseMsg.Answer {
			// parse ipv4
			if ipv4, ok := rr.(*dns.A); ok {
				ips = append(ips, &ipv4.A)
			}
			// parse ipv6
			if ipv6, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, &ipv6.AAAA)
			}
		}
	}

	return ips
}

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

func GetDefaultQueryMsg() *dns.Msg {
	msg := &dns.Msg{}

	// let's be cache friendly
	msg.MsgHdr = dns.MsgHdr{
		Id: 0,
	}

	return msg
}
