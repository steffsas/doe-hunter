package consumer

import (
	"encoding/json"
	"errors"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_RESINFO_CONSUMER_GROUP = "resinfo-scan-group"

type ResInfoProcessConsumer struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (resinfo *ResInfoProcessConsumer) Process(msg *kafka.Message, sh storage.StorageHandler) error {
	if msg == nil {
		return errors.New("message is nil")
	}

	// unmarshal kafka msg to scan
	resinfoScan := &scan.ResInfoScan{}
	err := json.Unmarshal(msg.Value, resinfoScan)
	if err != nil {
		logrus.Errorf("error unmarshaling ResInfo scan: %s", err.Error())
		return err
	}

	// process result
	resinfoScan.Meta.SetStarted()
	resinfo.StartResInfo(resinfoScan)
	resinfoScan.Meta.SetFinished()

	// store
	err = sh.Store(resinfoScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", resinfoScan.Meta.ScanId, err)
	}

	return err
}

func ParseResInfoResponse(m *dns.Msg) (*scan.ResInfoResult, error) {
	res := &scan.ResInfoResult{
		Keys: make([]string, 0),
	}

	if m == nil {
		return res, nil
	}

	resInfoRecordFound := false

	for _, a := range m.Answer {
		if a.Header().Rrtype == dns.TypeRESINFO {
			if resInfoRecordFound {
				// RFC 9606: "If the resolver understands the RESINFO RR type, the RRset MUST have exactly one record"
				logrus.Warnf("multiple RESINFO records found")
				res.MultipleRecords = true
			}

			resinfo, ok := a.(*dns.RESINFO)
			if !ok {
				logrus.Warnf("could not cast to RESINFO")
				return res, custom_errors.ErrParsingResInfo
			}
			res.Keys = append(res.Keys, resinfo.Txt...)

			res.RFC9606Support = true
			resInfoRecordFound = true
		}
	}
	return res, nil
}

func (resinfo *ResInfoProcessConsumer) StartResInfo(s *scan.ResInfoScan) {
	if s.Result == nil {
		s.Result = &scan.ResInfoResult{}
	}

	q := query.NewResInfoQuery(s.TargetName)
	q.Host = s.Host

	s.Meta.SetStarted()
	res, err := resinfo.QueryHandler.Query(q)
	s.Meta.SetFinished()
	if err != nil {
		logrus.Errorf("error querying %s: %v", s.Meta.ScanId, err)
		s.Meta.AddError(custom_errors.NewQueryError(err, true))
		return
	}

	s.Response = res
	result, parseErr := ParseResInfoResponse(res.Response.ResponseMsg)
	if parseErr != nil {
		s.Meta.AddError(custom_errors.NewQueryError(parseErr, true))
	} else {
		s.Result = result
	}
}
