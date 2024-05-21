package consumer

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_PTR_CONSUMER_GROUP = "ptr-scan-group"

type PTRProcessEventHandler struct {
	k.EventProcessHandler

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

func NewKafkaPTREventConsumer(config *k.KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_PTR_CONSUMER_GROUP
	}

	ph := &PTRProcessEventHandler{
		QueryHandler: query.NewPTRQueryHandler(),
	}

	kec, err = k.NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaPTRParallelEventConsumer(config *k.KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaParallelConsumer, err error) {
	if config == nil {
		config = k.GetDefaultKafkaParallelConsumerConfig(DEFAULT_PTR_CONSUMER_GROUP, k.DEFAULT_PTR_TOPIC)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (k.EventConsumer, error) {
		return NewKafkaPTREventConsumer(
			config.KafkaConsumerConfig,
			storageHandler,
		)
	}
	kec, err = k.NewKafkaParallelEventConsumer(createConsumerFunc, config.KafkaParallelEventConsumerConfig)

	if err != nil {
		logrus.Errorf("failed to create parallel consumer: %v", err)
	}

	return
}
