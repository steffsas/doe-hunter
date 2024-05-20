package query

import (
	"fmt"
	"time"

	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/helper"
)

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
