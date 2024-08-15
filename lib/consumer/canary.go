package consumer

import (
	"encoding/json"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_CANARY_CONSUMER_GROUP = "canary-scan-group"

type CanaryQueryHandler interface {
	Query(query *query.ConventionalDNSQuery) (response *query.ConventionalDNSResponse, err custom_errors.DoEErrors)
}

type CanaryProcessEventHandler struct {
	EventProcessHandler

	Producer     producer.ScanProducer
	QueryHandler CanaryQueryHandler
}

func (ph *CanaryProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	canaryScan := &scan.CanaryScan{}
	err := json.Unmarshal(msg.Value, canaryScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoT scan %s", err.Error())
		return err
	}

	// process
	var qErr custom_errors.DoEErrors
	canaryScan.Meta.SetStarted()
	canaryScan.Result, qErr = ph.QueryHandler.Query(canaryScan.Query)
	canaryScan.Meta.SetFinished()
	if qErr != nil {
		canaryScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoT scan %s to %s:%d: %s", canaryScan.Meta.ScanId, canaryScan.Query.Host, canaryScan.Query.Port, qErr.Error())
	}

	// store
	err = storage.Store(canaryScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", canaryScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaCanaryEventConsumer(
	config *KafkaConsumerConfig,
	prod producer.ScanProducer,
	storageHandler storage.StorageHandler,
	queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_CANARY_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &CanaryProcessEventHandler{
			Producer:     prod,
			QueryHandler: query.NewCanaryQueryHandler(queryConfig),
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
