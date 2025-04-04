package scan

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/svcb"
)

const DDR_SCAN_TYPE = "DDR"

type DDRScanMetaInformation struct {
	ScanMetaInformation

	IpVersion               string `json:"ip_version"`
	ScheduleDoEScans        bool   `json:"schedule_doe_scans"`
	ScheduleFingerprintScan bool   `json:"schedule_fingerprint_scan"`
	PTRScheduled            bool   `json:"ptr_scheduled"`
}

type DDRScan struct {
	Scan

	Meta   *DDRScanMetaInformation        `json:"meta"`
	Query  *query.ConventionalDNSQuery    `json:"query"`
	Result *query.ConventionalDNSResponse `json:"result"`
}

func (scan *DDRScan) Marshal() (bytes []byte, err error) {
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

func (scan *DDRScan) GetIdentifier() string {
	return fmt.Sprintf("%s|%s|%d",
		DDR_SCAN_TYPE,
		scan.Query.Host,
		scan.Query.Port)
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

	dnssecOrigins := []string{}

	for _, answer := range scan.Result.Response.ResponseMsg.Answer {
		svcbRecord, ok := answer.(*dns.SVCB)
		if !ok {
			logrus.Warnf("parsing DDR scan %s: could not cast DDR DNS answer to SVCB, ignore DNS RR", scan.Meta.ScanId)
			errorColl = append(errorColl, custom_errors.NewQueryError(custom_errors.ErrInvalidSVCBRR, false).AddInfoString("could not cast DNS answer to SVCB"))
			continue
		}

		svcb, err := svcb.ParseDDRSVCB(scan.Meta.ScanId, svcbRecord)
		errorColl = append(errorColl, err...)
		if custom_errors.ContainsCriticalErr(err) {
			logrus.Errorf("parsing DDR scan %s: critical error while parsing SVCB record, ignore DNS RR", scan.Meta.ScanId)
			continue
		}

		// create DNSSEC scan for host targetName (note that this scan still might not be added since it is not unique)
		dnssec := NewDDRDNSSECScan(svcb.Target, svcb.Target, scan.Meta.ScanId, scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint)
		if !slices.Contains(dnssecOrigins, dnssec.GetIdentifier()) {
			scans = append(scans, dnssec)
			dnssecOrigins = append(dnssecOrigins, dnssec.GetIdentifier())
		}

		// create DoE scans for each ALPN and ip hint
		for _, alpn := range svcb.Alpn.Alpn {
			s, e := produceScansFromAlpn(scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint, svcb.Target, svcb.Target, alpn, svcb)
			scans = append(scans, s...)
			errorColl = append(errorColl, e...)

			if svcb.IPv4Hint != nil {
				for _, ipv4 := range svcb.IPv4Hint.Hint {
					// create DoE scans for IPv4 hints
					s, e := produceScansFromAlpn(scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint, svcb.Target, ipv4.String(), alpn, svcb)
					scans = append(scans, s...)
					errorColl = append(errorColl, e...)

					// create DNSSEC scan (note that this scan still might not be added since it is not unique)
					dnssec := NewDDRDNSSECScan(svcb.Target, ipv4.String(), scan.Meta.ScanId, scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint)
					if !slices.Contains(dnssecOrigins, dnssec.GetIdentifier()) {
						scans = append(scans, dnssec)
						dnssecOrigins = append(dnssecOrigins, dnssec.GetIdentifier())
					}
				}
			}

			if svcb.IPv6Hint != nil {
				for _, ipv6 := range svcb.IPv6Hint.Hint {
					s, e := produceScansFromAlpn(scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint, svcb.Target, ipv6.String(), alpn, svcb)
					scans = append(scans, s...)
					errorColl = append(errorColl, e...)

					// create DNSSEC scan (note that this scan still might not be added since it is not unique)
					dnssec := NewDDRDNSSECScan(svcb.Target, ipv6.String(), scan.Meta.ScanId, scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint)
					if !slices.Contains(dnssecOrigins, dnssec.GetIdentifier()) {
						scans = append(scans, dnssec)
						dnssecOrigins = append(dnssecOrigins, dnssec.GetIdentifier())
					}
				}
			}

			// loop through glue records
			// hint: we scan for each IP as a host to detect misconfigurations/deltas in DNSSEC between the NS
			for _, g := range scan.Result.Response.ResponseMsg.Extra {
				if A, ok := g.(*dns.A); ok {
					// if there are multiple glue records, we should only consider those for the right target
					if A.Hdr.Name == svcb.Target {
						// // create DNSSEC scan (note that this scan still might not be added since it is not unique)
						dnssec := NewDDRDNSSECScan(svcb.Target, A.A.String(), scan.Meta.ScanId, scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint)
						if !slices.Contains(dnssecOrigins, dnssec.GetIdentifier()) {
							scans = append(scans, dnssec)
							dnssecOrigins = append(dnssecOrigins, dnssec.GetIdentifier())
						}
					}
				}

				if AAAA, ok := g.(*dns.AAAA); ok {
					// if there are multiple glue records, we should only consider those for the right target
					if AAAA.Hdr.Name == svcb.Target {
						// // create DNSSEC scan (note that this scan still might not be added since it is not unique)
						dnssec := NewDDRDNSSECScan(svcb.Target, AAAA.AAAA.String(), scan.Meta.ScanId, scan.Meta.ScanId, scan.Meta.RunId, scan.Meta.VantagePoint)
						if !slices.Contains(dnssecOrigins, dnssec.GetIdentifier()) {
							scans = append(scans, dnssec)
							dnssecOrigins = append(dnssecOrigins, dnssec.GetIdentifier())
						}
					}
				}
			}
		}
	}

	return scans, errorColl
}

func NewDDRScan(q *query.ConventionalDNSQuery, scheduleDoEScans bool, runId string, vantagePoint string) *DDRScan {
	if q == nil {
		q = query.NewDDRQuery()
	}

	scan := &DDRScan{
		Meta: &DDRScanMetaInformation{},
	}
	scan.Meta.ScheduleFingerprintScan = true
	scan.Meta.ScanMetaInformation = *NewScanMetaInformation("", "", runId, vantagePoint)
	scan.Meta.ScheduleDoEScans = scheduleDoEScans
	scan.Meta.VantagePoint = vantagePoint
	scan.Query = q
	return scan
}

// just append the errors to the DDRScan
func produceScansFromAlpn(
	parentScanId string,
	runId string,
	vantagePoint string,
	targetName string,
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

	// create query message for DoE
	queryMsg := query.GetDefaultQueryMsg()

	// create certificate query
	certQuery := query.NewCertificateQuery()
	certQuery.Host = host
	if host != targetName {
		certQuery.SNI = targetName
	}
	// set ALPN since some hosts require it to hand out the proper certificate
	if alpn != "" {
		certQuery.ALPN = []string{alpn}
	}

	var doeScan DoEScan

	switch alpn {
	case "doq":
		q := query.NewDoQQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		q.SNI = targetName
		if port != nil {
			q.Port = *port
		}
		doeScan = NewDoQScan(q, parentScanId, parentScanId, runId, vantagePoint)

		certQuery.ALPN = query.DOQ_TLS_PROTOCOLS
		certQuery.Port = doeScan.GetDoEQuery().Port

		logrus.Debugf("produced DoQ scan from ALPN %s for %s on %d with SNI %s", alpn, host, q.Port, targetName)
	case "dot":
		q := query.NewDoTQuery()
		q.Host = host
		q.QueryMsg = queryMsg
		q.SNI = targetName
		if port != nil {
			q.Port = *port
		}
		doeScan = NewDoTScan(q, parentScanId, parentScanId, runId, vantagePoint)

		// empty ALPN for DoT
		certQuery.Port = doeScan.GetDoEQuery().Port

		logrus.Debugf("produced DoT scan from ALPN %s for %s on %d with SNI %s", alpn, host, q.Port, targetName)
	case "h1", "http/1.0", "http/1.1":
		var dohScan *DoHScan
		dohScan, sErr := createDoHScan(parentScanId, runId, vantagePoint, queryMsg, host, targetName, query.HTTP_VERSION_1, port, dohpath)
		if sErr == nil || !sErr.IsCritical() {
			certQuery.Port = dohScan.Query.Port
			doeScan = dohScan

			logrus.Debugf("produced DoH http1 scan from ALPN %s for %s on %d with SNI %s", alpn, host, dohScan.Query.Port, targetName)
		} else {
			logrus.Warnf("got error on creating DoH scan %s:", sErr.Error())
		}

		if sErr != nil {
			err = append(err, sErr)
		}
	case "h2", "http/2", "doh":
		var dohScan *DoHScan
		dohScan, sErr := createDoHScan(parentScanId, runId, vantagePoint, queryMsg, host, targetName, query.HTTP_VERSION_2, port, dohpath)
		if sErr == nil || !sErr.IsCritical() {
			certQuery.Port = dohScan.Query.Port
			doeScan = dohScan

			logrus.Debugf("produced DoH http2 scan from ALPN %s for %s on %d with SNI %s", alpn, host, dohScan.Query.Port, targetName)
		} else {
			logrus.Warnf("got error on creating DoH scan %s:", sErr.Error())
		}

		if sErr != nil {
			err = append(err, sErr)
		}
	case "h3", "http/3":
		var dohScan *DoHScan
		dohScan, sErr := createDoHScan(parentScanId, runId, vantagePoint, queryMsg, host, targetName, query.HTTP_VERSION_3, port, dohpath)
		if sErr == nil || !sErr.IsCritical() {
			certQuery.Port = dohScan.Query.Port
			doeScan = dohScan

			logrus.Debugf("produced DoH http3 scan from ALPN %s for %s on %d with SNI %s", alpn, host, dohScan.Query.Port, targetName)
		} else {
			logrus.Warnf("got error on creating DoH scan %s:", sErr.Error())
		}

		if sErr != nil {
			err = append(err, sErr)
		}
	default:
		logrus.Warnf("parsing DDR scan %s: unknown ALPN %s in SVCB record, ignore", parentScanId, alpn)
		err = append(err, custom_errors.NewQueryError(custom_errors.ErrUnknownALPN, false).AddInfoString(fmt.Sprintf("ALPN %s for %s", alpn, host)))
	}

	if doeScan != nil {
		scans = append(scans, doeScan)

		// let's create an EDSR scan for the discovered protocol
		edsrScan := NewEDSRScan(targetName, host, alpn, doeScan.GetMetaInformation().ScanId, parentScanId, runId, vantagePoint)
		scans = append(scans, edsrScan)

		// Resinfo scan
		resInfoScan := NewResInfoScan(targetName, host, doeScan.GetMetaInformation().ScanId, parentScanId, runId, vantagePoint)
		scans = append(scans, resInfoScan)

		// create certificate scan
		certScan := NewCertificateScan(certQuery, parentScanId, doeScan.GetMetaInformation().ScanId, runId, vantagePoint)
		certScan.Meta.Children = []string{doeScan.GetMetaInformation().ScanId}
		scans = append(scans, certScan)
		logrus.Debugf("produced certificate scan for ALPN %s", alpn)
	}

	return
}

func createDoHScan(
	parentScanId string,
	runId string,
	vantagePoint string,
	queryMsg *dns.Msg,
	host string,
	targetName string,
	httpVersion string,
	port *int,
	dohpath *string,
) (*DoHScan, custom_errors.DoEErrors) {
	q := query.NewDoHQuery()
	q.Host = host
	q.QueryMsg = queryMsg
	q.HTTPVersion = httpVersion
	q.SNI = targetName

	if port != nil {
		q.Port = *port
	}

	scan := NewDoHScan(q, parentScanId, parentScanId, runId, vantagePoint)

	if dohpath != nil {
		q.URI = *dohpath
	} else {
		logrus.Warnf("parsing DDR scan %s: ALPN doh requires DoH path but none is given, fallback to default", parentScanId)
		pathErr := custom_errors.NewQueryError(custom_errors.ErrDoHPathNotProvided, false).AddInfoString("fallback to default path")
		return scan, pathErr
	}

	return scan, nil
}
