package scan

import (
	"encoding/json"
	"fmt"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/svcb"
)

const DDR_SCAN_TYPE = "DDR"

type DDRScanMetaInformation struct {
	ScanMetaInformation

	ScheduleDoEScans bool `json:"schedule_doe_scans"`
	PTRScheduled     bool `json:"ptr_scheduled"`
}

type DDRScan struct {
	Scan

	Meta   *DDRScanMetaInformation        `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`

	PTR []string `json:"ptr"`
}

func (scan *DDRScan) Marshall() (bytes []byte, err error) {
	return json.Marshal(scan)
}

func (scan *DDRScan) GetScanId() string {
	return scan.Meta.ScanId
}

func (scan *DDRScan) GetMetaInformation() *ScanMetaInformation {
	return &scan.Meta.ScanMetaInformation
}

func (scan *DDRScan) GetType() string {
	return DDR_SCAN_TYPE
}

func (scan *DDRScan) CreateScansFromResponse() ([]Scan, []custom_errors.DoEErrors) {
	scans := []Scan{}
	errorColl := []custom_errors.DoEErrors{}

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
		errorColl = append(errorColl, err...)
		if custom_errors.ContainsCriticalErr(err) {
			logrus.Errorf("parsing DDR scan %s: critical error while parsing SVCB record, ignore DNS RR", scan.Meta.ScanId)
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

	return scans, errorColl
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

// just append the errors to the DDRScan
func produceScanFromAlpn(
	parentScanId string,
	host string,
	alpn string,
	svcb *svcb.SVCBRR,
) (
	scans []Scan,
	err []custom_errors.DoEErrors,
) {
	scans = []Scan{}
	err = []custom_errors.DoEErrors{}

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
		scan, sErr := createDoHScan(parentScanId, queryMsg, host, query.HTTP_VERSION_2, port, dohpath)
		if sErr != nil {
			err = append(err, sErr)
		}

		scans = append(scans, scan)
	case "h1":
		scan, sErr := createDoHScan(parentScanId, queryMsg, host, query.HTTP_VERSION_1, port, dohpath)
		if sErr != nil {
			err = append(err, sErr)
		}

		scans = append(scans, scan)
	case "http/1.1":
		scan, sErr := createDoHScan(parentScanId, queryMsg, host, query.HTTP_VERSION_1, port, dohpath)
		if sErr != nil {
			err = append(err, sErr)
		}

		scans = append(scans, scan)
	case "h2":
		scan, sErr := createDoHScan(parentScanId, queryMsg, host, query.HTTP_VERSION_2, port, dohpath)
		if sErr != nil {
			err = append(err, sErr)
		}

		scans = append(scans, scan)
	case "h3":
		scan, sErr := createDoHScan(parentScanId, queryMsg, host, query.HTTP_VERSION_3, port, dohpath)
		if sErr != nil {
			err = append(err, sErr)
		}

		scans = append(scans, scan)
	default:
		logrus.Warnf("parsing DDR scan %s: unknown ALPN %s in SVCB record, ignore", parentScanId, alpn)
		err = append(err, custom_errors.NewQueryError(custom_errors.ErrUnknownALPN, false).AddInfoString(fmt.Sprintf("ALPN %s for %s", alpn, host)))
	}

	return
}

func createDoHScan(
	parentScanId string,
	queryMsg *dns.Msg,
	host string,
	httpVersion string,
	port *int,
	dohpath *string,
) (*DoHScan, custom_errors.DoEErrors) {
	q := query.NewDoHQuery()
	q.Host = host
	q.QueryMsg = queryMsg
	q.HTTPVersion = httpVersion

	if port != nil {
		q.Port = *port
	}

	scan := NewDoHScan(q, parentScanId, parentScanId)

	if dohpath != nil {
		q.URI = *dohpath
	} else {
		logrus.Warnf("parsing DDR scan %s: ALPN doh requires DoH path but none is given, fallback to default", parentScanId)
		pathErr := custom_errors.NewQueryError(custom_errors.ErrDoHPathNotProvided, false).AddInfoString("fallback to default path")
		// let's add this information already
		scan.Meta.AddError(pathErr)
		return scan, pathErr
	}

	return scan, nil
}
