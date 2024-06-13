package consumer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

// TODO change this?
// nolint: gochecknoglobals
var RESOLVER = net.IP{8, 8, 8, 8}

type EDSRProcessConsumer struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (edsr *EDSRProcessConsumer) ProcessScan(msg *kafka.Message, sh storage.StorageHandler) error {
	if msg == nil {
		return errors.New("message is nil")
	}

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
	// let's create the first hop's query
	q := query.NewEDSRQuery(s.TargetName)
	q.Host = s.Host

	// let's add the ips of the host we start with to the already considered hosts
	consideredIPs, err := query.ResolveHost(q.Host, RESOLVER, edsr.QueryHandler)
	if err != nil {
		logrus.Errorf("error resolving host %s: %s", q.Host, err.Error())
		s.Meta.AddError(custom_errors.NewQueryError(custom_errors.ErrResolvingHost, true).AddInfoString(fmt.Sprintf("error resolving host %s: %s", q.Host, err.Error())))
		return
	}

	// first hop was hostname but IP could not be resolved, so we do not start to search for redirections
	if net.ParseIP(q.Host) == nil && len(consideredIPs) == 0 {
		logrus.Errorf("error resolving host %s: no IPs found", q.Host)
		s.Meta.AddError(custom_errors.NewQueryError(custom_errors.ErrResolvingHost, true).AddInfoString(fmt.Sprintf("error resolving host %s: no IPs found", q.Host)))
		return
	}

	consideredIPsPointer := &consideredIPs

	// -1 because NewEDSRHop takes parentHop counter and increments it by 1
	initialHop := scan.NewEDSRHop(-1, q)
	s.Result.Redirections = append(s.Result.Redirections, initialHop)

	// let's create a channel
	hops := []*scan.EDSRHop{initialHop}

	for len(hops) > 0 {
		nextHop := hops[0]
		hops = hops[1:]

		logrus.Debug("query hop", nextHop)

		// query hop
		nextHops, err := edsr.QueryHop(nextHop, s.Meta.ScanId, s.Protocol, s.TargetName, &consideredIPsPointer)
		if err != nil {
			s.Meta.AddError(err)
		}

		logrus.Debug("got new next hops", nextHops)

		// edsr can be executed if we have at least one redirection
		if len(nextHops) > 0 {
			s.Result.EDSRDetected = true
		}

		// let's schedule next hops
		for _, nextHop := range nextHops {
			s.Result.Redirections = append(s.Result.Redirections, nextHop)
			hops = append(hops, nextHop)
		}

		// connect hops since the glue records can contain in multiple IPv4 and IPv6 glue records
		ConnectHops(s.Result.Redirections)
	}

	logrus.Debugf("Considered the following %d IPs", len(*consideredIPsPointer))
}

func (edsr *EDSRProcessConsumer) QueryHop(
	hop *scan.EDSRHop, scanId string, protocol string, targetName string, consideredIPs **[]*net.IP) (nextHops []*scan.EDSRHop, err custom_errors.DoEErrors) {
	if hop.Query == nil {
		err := custom_errors.NewQueryError(custom_errors.ErrQueryNil, true).AddInfoString("query for hop is nil")
		hop.Errors = append(hop.Errors, err)
		return nil, err
	}

	// query
	res, err := edsr.QueryHandler.Query(hop.Query)
	if err != nil {
		hop.Errors = append(hop.Errors, err)
		return nil, err
	}

	// add result to hop
	hop.Result = res

	// check whether the SVCBs contain the necessary DoE protocol in this hop
	// errColl will contain a critical error if the resolver does not advertise the protocol
	svcbRR, errColl := scan.CheckForDoEProtocol(scanId, targetName, protocol, res)
	if len(errColl) > 0 {
		hop.Errors = append(hop.Errors, errColl...)
		if custom_errors.ContainsCriticalErr(errColl) {
			return nil, nil
		}
	}

	// let's safe this for later analysis
	hop.ConsideredSVCB = svcbRR

	if len(res.Response.ResponseMsg.Extra) == 0 {
		// we have no glue records, so we can terminate according to the protocol
		hop.Errors = append(hop.Errors, custom_errors.NewQueryError(custom_errors.ErrNoGlueRecords, false))
		return nil, nil
	}

	// check if we have a loop
	intersectingIPs := []*net.IP{}
	differenceIPs := []*net.IP{}
	for _, glueRecord := range res.Response.ResponseMsg.Extra {
		resGlueRR := &scan.GlueRecord{
			IP:   nil,
			Host: glueRecord.Header().Name,
		}

		// parse glue records
		if aRecord, ok := glueRecord.(*dns.A); ok {
			resGlueRR.IP = aRecord.A

			if glueRecord.Header().Name == targetName {
				if !isConsideredAlready(**consideredIPs, aRecord.A) {
					differenceIPs = append(differenceIPs, &aRecord.A)
				} else {
					intersectingIPs = append(intersectingIPs, &aRecord.A)
				}
			}
		}

		if aaaaRecord, ok := glueRecord.(*dns.AAAA); ok {
			resGlueRR.IP = aaaaRecord.AAAA

			if glueRecord.Header().Name == targetName {
				if !isConsideredAlready(**consideredIPs, aaaaRecord.AAAA) {
					differenceIPs = append(differenceIPs, &aaaaRecord.AAAA)
				} else {
					intersectingIPs = append(intersectingIPs, &aaaaRecord.AAAA)
				}
			}
		}

		// let's only append glue records of type A/AAAA
		if resGlueRR.IP != nil {
			hop.GlueRecords = append(hop.GlueRecords, resGlueRR)
		}
	}

	logrus.Debugf("EDSR intersecting IPs %v from considered IPs %v", intersectingIPs, consideredIPs)
	logrus.Debugf("EDSR difference IPs %v from considered IPs %v", differenceIPs, consideredIPs)

	// create hops from difference IPs
	for _, ip := range differenceIPs {
		// create new hop
		q := query.NewConventionalQuery()
		q.Host = ip.String()
		q.QueryMsg = hop.Query.QueryMsg.Copy()

		// create new child node (hop)
		newChild := scan.NewEDSRHop(hop.Hop, q)

		// set child node
		hop.ChildNodes = append(hop.ChildNodes, newChild.Id)

		nextHops = append(nextHops, newChild)
		tmpConsideredIPs := append(**consideredIPs, ip)
		*consideredIPs = &tmpConsideredIPs
	}

	return
}

func ConnectHops(hops []*scan.EDSRHop) {
	// connect hops
	for _, hop := range hops {
		for _, glue := range hop.GlueRecords {
			for _, potentialChild := range hops {
				if potentialChild.Query.Host == glue.IP.String() && !HopContainsChild(hop, potentialChild.Id) {
					hop.ChildNodes = append(hop.ChildNodes, potentialChild.Id)
				}
			}
		}
	}
}

func HopContainsChild(hop *scan.EDSRHop, childId string) bool {
	for _, child := range hop.ChildNodes {
		if child == childId {
			return true
		}
	}

	return false
}

func isConsideredAlready(consideredIPs []*net.IP, ip net.IP) bool {
	for _, cIP := range consideredIPs {
		if cIP.Equal(ip) {
			return true
		}
	}

	return false
}
