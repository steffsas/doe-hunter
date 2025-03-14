package consumer

import (
	"encoding/json"
	"errors"
	"fmt"

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
	res := &scan.ResInfoResult{}

	if m == nil {
		return res, nil
	}

	resInfoRecordFound := false

	for _, a := range m.Answer {
		if a.Header().Rrtype == query.TypeRESINFO {
			if resInfoRecordFound {
				// RFC 9606: "If the resolver understands the RESINFO RR type, the RRset MUST have exactly one record"
				logrus.Warnf("multiple RESINFO records found")
			}

			// RESINFO uses the same format as structured TXT record
			// But we need to parse it as an unknown record (RFC3597)

			n, ok := a.(*dns.RFC3597)
			if !ok {
				logrus.Warnf("could not cast to RFC3597")
				return res, custom_errors.ErrParsingResInfo
			}

			data := n.Rdata

			dataBytes := make([]byte, len(data)/2)
			for i := 0; i < len(data); i += 2 {
				_, err := fmt.Sscanf(data[i:i+2], "%02x", &dataBytes[i/2])
				if err != nil {
					logrus.Warnf("error parsing RESINFO record: %v", err)
					return res, custom_errors.ErrParsingResInfo
				}
			}

			for i := 0; i < len(dataBytes); {
				// Parse key
				if i >= len(dataBytes) {
					logrus.Warnf("invalid key length in RESINFO record")
					return res, custom_errors.ErrParsingResInfo
				}
				keyLen := int(dataBytes[i])
				if i+keyLen > len(dataBytes) {
					logrus.Warnf("invalid key length in RESINFO record")
					return res, custom_errors.ErrParsingResInfo
				}
				key := string(dataBytes[i+1 : i+1+keyLen])
				i += 1 + keyLen

				res.Keys = append(res.Keys, key)
			}

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
