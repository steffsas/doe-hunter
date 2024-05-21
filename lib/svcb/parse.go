package svcb

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
)

type SVCBRR struct {
	Target   string
	Alpn     *dns.SVCBAlpn
	Port     *dns.SVCBPort
	IPv4Hint *dns.SVCBIPv4Hint
	IPv6Hint *dns.SVCBIPv6Hint
	DoHPath  *dns.SVCBDoHPath
	// see https://datatracker.ietf.org/doc/rfc9540/
	ODoH bool
}

func ParseDDRSVCB(scanId string, rr *dns.SVCB) (*SVCBRR, []custom_errors.DoEErrors) {
	svcb := &SVCBRR{}
	svcb.Alpn = &dns.SVCBAlpn{}
	svcb.Target = rr.Target
	svcb.ODoH = false

	errs := []custom_errors.DoEErrors{}

	for _, value := range rr.Value {
		switch value.Key() {
		case dns.SVCB_ALPN:
			alpn, ok := value.(*dns.SVCBAlpn)
			if !ok {
				logrus.Errorf("parsing DDR scan %s: could not cast SVCB value %s to ALPN", scanId, value.String())
				err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, true).AddInfoString(fmt.Sprintf("could not cast SVCB value %s to ALPN", value.String()))
				errs = append(errs, err)
				return nil, errs
			}
			svcb.Alpn = alpn
		case dns.SVCB_PORT:
			port, ok := value.(*dns.SVCBPort)
			if !ok {
				// fmt.Errorf("parsing DDR scan %s: could not cast SVCB value %s to Port", scanId, value.String())
				err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, true).AddInfoString(fmt.Sprintf("could not cast SVCB value %s to port", value.String()))
				errs = append(errs, err)
				return nil, errs
			}
			svcb.Port = port
		case dns.SVCB_IPV4HINT:
			ipv4hint, ok := value.(*dns.SVCBIPv4Hint)
			if !ok {
				logrus.Warnf("parsing DDR scan %s: Could not cast SVCB value %s to IPv4Hint, ignore IPv4 hint", scanId, value.String())
				err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, false).AddInfoString(fmt.Sprintf("could not cast SVCB value %s to IPv4Hint", value.String()))
				errs = append(errs, err)
			} else {
				svcb.IPv4Hint = ipv4hint
			}
		case dns.SVCB_IPV6HINT:
			ipv6hint, ok := value.(*dns.SVCBIPv6Hint)
			if !ok {
				logrus.Warnf("parsing DDR scan %s: Could not cast SVCB value %s to IPv6Hint, ignore IPv6 hint", scanId, value.String())
				err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, false).AddInfoString(fmt.Sprintf("could not cast SVCB value %s to IPv6Hint", value.String()))
				errs = append(errs, err)
			} else {
				svcb.IPv6Hint = ipv6hint
			}
		case dns.SVCB_DOHPATH:
			dohPath, ok := value.(*dns.SVCBDoHPath)
			if !ok {
				logrus.Warnf("parsing DDR scan %s: Could not cast SVCB value %s to DoHPath", scanId, value.String())
				err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, true).AddInfoString(fmt.Sprintf("could not cast SVCB value %s to DoHPath", value.String()))
				errs = append(errs, err)
				return nil, errs
			} else {
				svcb.DoHPath = dohPath
			}
		// this is not yet implemented in miekg/dns
		// OHTTP, see https://www.rfc-editor.org/rfc/rfc9540.html#name-svcb-service-parameter
		case 8:
			svcb.ODoH = true
		default:
			logrus.Warnf("parsing DDR scan %s: got unknown SVCB key %s and value %s, ignore", scanId, value.Key(), value.String())
			err := custom_errors.NewQueryError(custom_errors.ErrUnknownSvcbKey, false).
				AddInfoString(fmt.Sprintf("key: %d, value: %s", value.Key(), value.String()))
			errs = append(errs, err)
		}
	}

	// check SVCBs
	if len(svcb.Alpn.Alpn) == 0 {
		logrus.Errorf("parsing DDR scan %s: ALPN is empty", scanId)
		err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, true).AddInfoString("ALPN is empty")
		errs = append(errs, err)
		return nil, errs
	}

	if len(svcb.Target) == 0 {
		logrus.Errorf("parsing DDR scan %s: targetName is empty", scanId)
		err := custom_errors.NewQueryError(custom_errors.ErrParsingSvcbKey, true).AddInfoString("targetName is empty")
		errs = append(errs, err)
		// it is critical because it violates RFC9462
		return nil, errs
	}

	return svcb, errs
}
