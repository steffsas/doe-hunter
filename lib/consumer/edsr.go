package consumer

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
	"github.com/steffsas/doe-hunter/lib/svcb"
)

type EDSRProcessConsumer struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (edsr *EDSRProcessConsumer) ProcessScan(msg *kafka.Message, sh storage.StorageHandler) error {
	// unmarshal kafka msg to scan
	edsrScan := &scan.EDSRScan{}
	err := json.Unmarshal(msg.Value, edsrScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DDR scan: %s", err.Error())
		return err
	}

	// process result
	edsr.StartEDSR(edsrScan)

	return nil
}

func (edsr *EDSRProcessConsumer) StartEDSR(s *scan.EDSRScan) {
	// query targetNames' ip addresses
	ips, err := edsr.ResolveTargetName(s.TargetName)
	if err != nil {
		s.Meta.AddError(err)
		s.Meta.AddError(custom_errors.NewQueryError(custom_errors.ErrResolvingIPsOfTargetName, true))
		logrus.Errorf("Could not resolve IPv4 or IPv6 addresses of %s", s.TargetName)
		return
	}
	logrus.Debug("Resolved IPs", ips)

	initialHop := scan.NewEDSRHop("", 0, s.Query)
	s.Result.Redirections = append(s.Result.Redirections, initialHop)

	// let's create a channel
	hops := []*scan.EDSRHop{initialHop}

	consideredIPPointer := &ips

	for len(hops) > 0 {
		nextHop := hops[0]
		hops = hops[1:]

		logrus.Debug("query hop", nextHop)

		// query hop
		nextHops := edsr.QueryHop(nextHop, s.Meta.ScanId, s.Protocol, s.TargetName, &consideredIPPointer)

		logrus.Debug("got new next hops", nextHops)

		// let's schedule next hops
		for _, nextHop := range nextHops {
			s.Result.Redirections = append(s.Result.Redirections, nextHop)
			hops = append(hops, nextHop)
		}
	}
}

func (edsr *EDSRProcessConsumer) ResolveTargetName(targetName string) (targetNameIPs []*net.IP, err custom_errors.DoEErrors) {
	// check whether targetName is IP
	targetNameIP := net.ParseIP(targetName)
	if targetNameIP != nil {
		targetNameIPs = append(targetNameIPs, &targetNameIP)
		return
	}

	// we have a hostname, let's resolve it's IPv4
	ipv4query := query.NewConventionalQuery()
	ipv4query.Host = "8.8.8.8"
	ipv4query.Port = 53
	ipv4query.QueryMsg.SetQuestion(targetName, dns.TypeA)

	res, err := edsr.QueryHandler.Query(ipv4query)
	if err != nil {
		return
	}

	targetNameIPs = append(targetNameIPs, query.ParseIPAddresses(res)...)

	// let's resolve IPv6 addresses
	ipv6query := query.NewConventionalQuery()
	ipv6query.Host = "8.8.8.8"
	ipv6query.Port = 53
	ipv6query.QueryMsg.SetQuestion(targetName, dns.TypeAAAA)

	res, err = edsr.QueryHandler.Query(ipv6query)
	if err != nil {
		return
	}

	targetNameIPs = append(targetNameIPs, query.ParseIPAddresses(res)...)

	return
}

func (edsr *EDSRProcessConsumer) QueryHop(
	hop *scan.EDSRHop, scanId string, protocol string, targetName string, consideredIPs **[]*net.IP) (
	nextHops []*scan.EDSRHop,
) {
	if hop.Query == nil {
		hop.Errors = append(hop.Errors, custom_errors.NewQueryError(custom_errors.ErrQueryNil, true).AddInfoString("query for hop is nil"))
		return nil
	}

	// query
	res, err := edsr.QueryHandler.Query(hop.Query)
	if err != nil {
		hop.Errors = append(hop.Errors, err)
		return nil
	}

	// add result to hop
	hop.Result = res

	if len(res.Response.ResponseMsg.Extra) == 0 {
		// we have no glue records, so we can terminate according to the protocol
		hop.Errors = append(hop.Errors, custom_errors.NewQueryError(custom_errors.ErrNoGlueRecords, false))
		return nil
	}

	// check whether the SVCBs contain the necessary DoE protocol in this hop
	// errColl will contain a critical error if the resolver does not advertise the protocol
	errColl := edsr.CheckForDoEProtocol(scanId, targetName, protocol, res)
	if len(errColl) > 0 {
		hop.Errors = append(hop.Errors, errColl...)
		if custom_errors.ContainsCriticalErr(errColl) {
			return nil
		}
	}

	// check if we have a loop
	intersectingIPs := []*net.IP{}
	differenceIPs := []*net.IP{}
	for _, glueRecord := range res.Response.ResponseMsg.Extra {
		if glueRecord.Header().Name == targetName {
			// try to parse A record
			if aRecord, ok := glueRecord.(*dns.A); ok {
				// do smth
				if !isConsideredAlready(**consideredIPs, aRecord.A) {
					differenceIPs = append(differenceIPs, &aRecord.A)
				} else {
					intersectingIPs = append(intersectingIPs, &aRecord.A)
				}
			} else if aaaaRecord, ok := glueRecord.(*dns.AAAA); ok {
				if !isConsideredAlready(**consideredIPs, aaaaRecord.AAAA) {
					differenceIPs = append(differenceIPs, &aaaaRecord.AAAA)
				} else {
					intersectingIPs = append(intersectingIPs, &aaaaRecord.AAAA)
				}
			}
		}
	}

	logrus.Infof("EDSR intersecting IPs %v from considered IPs %v", intersectingIPs, consideredIPs)
	logrus.Infof("EDSR difference IPs %v from considered IPs %v", differenceIPs, consideredIPs)

	// create hops from difference IPs
	for _, ip := range differenceIPs {
		// create new hop
		q := query.NewConventionalQuery()
		q.Host = ip.String()
		q.Port = 53
		q.QueryMsg = hop.Query.QueryMsg.Copy()
		nextHops = append(nextHops, scan.NewEDSRHop(hop.Id, hop.Hop, hop.Query))
		tmpConsideredIPs := append(**consideredIPs, ip)
		*consideredIPs = &tmpConsideredIPs
	}

	return
}

func (edsr *EDSRProcessConsumer) CheckForDoEProtocol(scanId string, targetName string, protocol string, res *query.ConventionalDNSResponse) (errColl []custom_errors.DoEErrors) {
	if (res == nil) || (res.Response == nil) || (res.Response.ResponseMsg == nil) {
		return append(errColl, custom_errors.NewQueryError(custom_errors.ErrNoResponse, true).AddInfoString("response is empty"))
	}

	for _, answer := range res.Response.ResponseMsg.Answer {
		svcbRecord, ok := answer.(*dns.SVCB)
		if !ok {
			errColl = append(errColl, custom_errors.NewQueryError(custom_errors.ErrInvalidSVCBRR, false).AddInfoString("could not cast DNS answer to SVCB"))
			continue
		}

		// see https://www.ietf.org/id/draft-jt-add-dns-server-redirection-04.html, strict origin redirection
		if svcbRecord.Target != targetName {
			continue
		}

		// parse SVCB record
		svcbEntry, err := svcb.ParseDDRSVCB(scanId, svcbRecord)
		errColl = append(errColl, err...)
		if custom_errors.ContainsCriticalErr(err) {
			logrus.Errorf("parsing EDSR scan %s: critical error while parsing SVCB record, ignore DNS RR", scanId)
			continue
		}

		for _, alpn := range svcbEntry.Alpn.Alpn {
			if alpn == protocol {
				// we found an SVCB record to the same protocol with a lower priority than the current one
				return errColl
			}
		}
	}

	return append(errColl,
		custom_errors.NewQueryError(custom_errors.ErrResolverDoesNotAdvertiseProtocol, true).
			AddInfoString(fmt.Sprintf("resolver does not advertise protocol %s", protocol)))
}

func isConsideredAlready(consideredIPs []*net.IP, ip net.IP) bool {
	for _, cIP := range consideredIPs {
		if cIP.Equal(ip) {
			return true
		}
	}

	return false
}
