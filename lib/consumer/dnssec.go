package consumer

import (
	"encoding/json"
	"errors"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DNSSEC_CONSUMER_GROUP = "dnssec-scan-group"

type DNSSECProcessConsumer struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (dpc *DNSSECProcessConsumer) Process(msg *kafka.Message, sh storage.StorageHandler) error {
	if msg == nil {
		return errors.New("message is nil")
	}

	// unmarshal kafka msg to scan
	dnssecScan := &scan.DNSSECScan{}
	err := json.Unmarshal(msg.Value, dnssecScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DDR scan: %s", err.Error())
		return err
	}

	// process result
	// process
	var qErr custom_errors.DoEErrors
	dnssecScan.Meta.SetStarted()
	dnssecScan.Result, qErr = dpc.QueryHandler.Query(dnssecScan.Query)
	dnssecScan.Meta.SetFinished()
	if qErr != nil {
		dnssecScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoH scan %s to %s:%d: %s", dnssecScan.Meta.ScanId, dnssecScan.Query.Host, dnssecScan.Query.Port, qErr.Error())
	}

	// store
	err = sh.Store(dnssecScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", dnssecScan.Meta.ScanId, err)
	}

	return err
}

func NewKafkaDNSSECEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler, queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DNSSEC_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &EDSRProcessConsumer{
			QueryHandler: query.NewConventionalDNSQueryHandler(queryConfig),
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
