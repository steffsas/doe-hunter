package scan

import (
	"encoding/json"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/svcb"
)

const DDR_SCAN_TYPE = "DDR"

type DDRScanMetaInformation struct {
	ScanMetaInformation
	ScheduleDoEScans bool `json:"schedule_doe_scans"`
}

type DDRScan struct {
	Meta   *DDRScanMetaInformation        `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func (scan *DDRScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DDRScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DDRScan) GetType() string {
	return DDR_SCAN_TYPE
}

func (scan *DDRScan) CreateScansFromResponse() (scans []Scan, errorColl []error) {
	scans = []Scan{}
	errorColl = []error{}

	if scan.Result == nil {
		return scans, nil
	}

	if scan.Result.Response == nil {
		return scans, nil
	}

	if scan.Result.Response.ResponseMsg == nil {
		return scans, nil
	}

	for _, answer := range scan.Result.Response.ResponseMsg.Answer {
		svcRecord, ok := answer.(*dns.SVCB)
		if !ok {
			logrus.Warnf("parsing DDR scan %s: could not cast DDR DNS answer to SVCB, ignore DNS RR", scan.Meta.ScanId)
			continue
		}

		svcb, err := svcb.ParseDDRSVCB(scan.Meta.ScanId, svcRecord)
		if err != nil {
			logrus.Error(err.Error())
			errorColl = append(errorColl, err)
			continue
		}

		for _, alpn := range svcb.Alpn.Alpn {
			s, e := produceScanFromAlpn(scan.Meta.ScanId, svcb.Target, alpn, svcb)
			scans = append(scans, s...)
			errorColl = append(errorColl, e...)

			if svcb.IPv4Hint != nil {
				for _, ipv4 := range svcb.IPv4Hint.Hint {
					s, e := produceScanFromAlpn(scan.Meta.ScanId, ipv4.String(), alpn, svcb)
					scans = append(scans, s...)
					errorColl = append(errorColl, e...)
				}
			}

			if svcb.IPv6Hint != nil {
				for _, ipv6 := range svcb.IPv6Hint.Hint {
					s, e := produceScanFromAlpn(scan.Meta.ScanId, ipv6.String(), alpn, svcb)
					scans = append(scans, s...)
					errorColl = append(errorColl, e...)
				}
			}
		}
	}

	return
}

func NewDDRScan(query *query.ConventionalDNSQuery, scheduleDoEScans bool) *DDRScan {
	scan := &DDRScan{
		Meta: &DDRScanMetaInformation{},
	}
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation("", "")
	scan.Meta.ScheduleDoEScans = scheduleDoEScans
	scan.Query = query
	return scan
}

func produceScanFromAlpn(parentScanId string, host string, alpn string, svcb *svcb.SVCBRR) (scans []Scan, err []error) {
	scans = []Scan{}
	err = []error{}

	var port *int
	if svcb.Port != nil {
		p := int(svcb.Port.Port)
		port = &p
	}

	var dohpath *string
	if svcb.DoHPath != nil {
		dohpath = &svcb.DoHPath.Template
	}

	queryMsg := new(dns.Msg)
	queryMsg.SetQuestion("google.de.", dns.TypeA)

	switch alpn {
	case "doq":
		q := query.NewDoQQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		scans = append(scans, NewDoQScan(q, parentScanId, parentScanId))
	case "dot":
		q := query.NewDoTQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		scans = append(scans, NewDoTScan(q, parentScanId, parentScanId))
	case "doh":
		q := query.NewDoHQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		if dohpath != nil {
			q.URI = *dohpath
		} else {
			logrus.Warnf("parsing DDR scan %s: ALPN doh requires DoH path but none is given, fallback to default", parentScanId)
		}
		scans = append(scans, NewDoHScan(q, parentScanId, parentScanId))
	case "h1":
		q := query.NewDoHQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		if dohpath != nil {
			q.URI = *dohpath
		} else {
			logrus.Warnf("parsing DDR scan %s: ALPN h1 requires DoH path but none is given, fallback to default", parentScanId)
		}
		q.HTTPVersion = query.HTTP_VERSION_1
		scans = append(scans, NewDoHScan(q, parentScanId, parentScanId))
	case "http/1.1":
		q := query.NewDoHQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		if dohpath != nil {
			q.URI = *dohpath
		} else {
			logrus.Warnf("parsing DDR scan %s: ALPN http/1.1 requires DoH path but none is given, fallback to default", parentScanId)
		}
		q.HTTPVersion = query.HTTP_VERSION_1
		scans = append(scans, NewDoHScan(q, parentScanId, parentScanId))
	case "h2":
		q := query.NewDoHQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		if dohpath != nil {
			q.URI = *dohpath
		} else {
			logrus.Warnf("parsing DDR scan %s: ALPN h2 requires DoH path but none is given, fallback to default", parentScanId)
		}
		q.HTTPVersion = query.HTTP_VERSION_2
		scans = append(scans, NewDoHScan(q, parentScanId, parentScanId))
	case "h3":
		q := query.NewDoHQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		if port != nil {
			q.Port = *port
		}
		if dohpath != nil {
			q.URI = *dohpath
		} else {
			logrus.Warnf("parsing DDR scan %s: ALPN h3 requires DoH path but none is given, fallback to default", parentScanId)
		}
		q.HTTPVersion = query.HTTP_VERSION_3
		scans = append(scans, NewDoHScan(q, parentScanId, parentScanId))
	default:
		logrus.Warnf("parsing DDR scan %s: unknown ALPN %s in SVCB record, ignore", parentScanId, alpn)
	}

	return
}
