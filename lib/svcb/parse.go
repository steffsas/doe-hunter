package svcb

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type SVCBRR struct {
	Target   string
	Alpn     *dns.SVCBAlpn
	Port     *dns.SVCBPort
	IPv4Hint *dns.SVCBIPv4Hint
	IPv6Hint *dns.SVCBIPv6Hint
	DoHPath  *dns.SVCBDoHPath
}

func ParseDDRSVCB(scanId string, rr *dns.SVCB) (svcb *SVCBRR, err error) {
	svcb = &SVCBRR{}

	svcb.Target = rr.Target

	for _, value := range rr.Value {
		switch value.Key() {
		case dns.SVCB_ALPN:
			alpn, ok := value.(*dns.SVCBAlpn)
			if !ok {
				return nil, fmt.Errorf("parsing DDR scan %s: could not cast SVCB value %s to ALPN", scanId, value.String())
			}
			svcb.Alpn = alpn
		case dns.SVCB_PORT:
			port, ok := value.(*dns.SVCBPort)
			if !ok {
				return nil, fmt.Errorf("parsing DDR scan %s: could not cast SVCB value %s to Port", scanId, value.String())
			}
			svcb.Port = port
		case dns.SVCB_IPV4HINT:
			ipv4hint, ok := value.(*dns.SVCBIPv4Hint)
			if !ok {
				logrus.Warnf("parsing DDR scan %s: Could not cast SVCB value %s to IPv4Hint, ignore IPv4 hint", scanId, value.String())
			} else {
				svcb.IPv4Hint = ipv4hint
			}
		case dns.SVCB_IPV6HINT:
			ipv6hint, ok := value.(*dns.SVCBIPv6Hint)
			if !ok {
				logrus.Warnf("parsing DDR scan %s: Could not cast SVCB value %s to IPv6Hint, ignore IPv6 hint", scanId, value.String())
			} else {
				svcb.IPv6Hint = ipv6hint
			}
		case dns.SVCB_DOHPATH:
			dohPath, ok := value.(*dns.SVCBDoHPath)
			if !ok {
				return nil, fmt.Errorf("parsing DDR scan %s: could not cast SVCB value %s to DoHPath", scanId, value.String())
			} else {
				svcb.DoHPath = dohPath
			}
		default:
			logrus.Warnf("parsing DDR scan %s: got unknown SVCB key %s and value %s, ignore", scanId, value.Key(), value.String())
		}
	}

	// check SVCBs
	if len(svcb.Alpn.Alpn) == 0 {
		return nil, fmt.Errorf("parsing DDR scan %s: ALPN is empty", scanId)
	}

	if len(svcb.Target) == 0 {
		return nil, fmt.Errorf("parsing DDR scan %s: Target is empty", scanId)
	}

	return
}
