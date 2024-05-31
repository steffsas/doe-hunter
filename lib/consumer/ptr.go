package consumer

import (
	"encoding/json"
	"strings"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_PTR_CONSUMER_GROUP = "ptr-scan-group"

type PTRProcessEventHandler struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (ph *PTRProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	ptrScan := &scan.PTRScan{}
	err := json.Unmarshal(msg.Value, ptrScan)
	if err != nil {
		return err
	}

	// process
	var qErr custom_errors.DoEErrors
	ptrScan.Meta.SetStarted()
	ptrScan.Result, qErr = ph.QueryHandler.Query(ptrScan.Query)
	ptrScan.Meta.SetFinished()
	if qErr != nil {
		if !strings.Contains(qErr.Error(), custom_errors.ErrNoResponse.Error()) {
			logrus.Errorf("error processing PTR scan %s: %s", ptrScan.Meta.ScanId, qErr.Error())
		}
		ptrScan.Meta.AddError(qErr)
	}

	// store
	err = storage.Store(ptrScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", ptrScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaPTREventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler, queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_PTR_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &PTRProcessEventHandler{
			QueryHandler: query.NewConventionalDNSQueryHandler(queryConfig),
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
