package consumer

import (
	"encoding/json"
	"errors"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DOQ_CONSUMER_GROUP = "doq-scan-group"

type DoQProcessEventHandler struct {
	k.EventProcessHandler

	QueryHandler *query.DoQQueryHandler
}

func (ph *DoQProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	doqScan := &scan.DoQScan{}
	err = json.Unmarshal(msg.Value, doqScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoQ scan %s: %s", doqScan.Meta.ScanId, err.Error())
		return err
	}

	// process
	// process
	var qErr custom_errors.DoEErrors
	doqScan.Meta.SetStarted()
	doqScan.Result, qErr = ph.QueryHandler.Query(doqScan.Query)
	doqScan.Meta.SetFinished()
	if qErr != nil {
		doqScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoQ scan %s to %s:%d: %s", doqScan.Meta.ScanId, doqScan.Query.Host, doqScan.Query.Port, qErr.Error())
	}

	RedoDoEScanOnCertError(
		qErr,
		doqScan,
		scan.NewDoQScan(doqScan.Query, doqScan.Meta.ScanId, doqScan.Meta.RootScanId),
		k.DEFAULT_DOT_TOPIC,
	)

	// store
	err = storage.Store(doqScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", doqScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaDoQEventConsumer(config *k.KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOQ_CONSUMER_GROUP
	}

	ph := &DoQProcessEventHandler{
		QueryHandler: query.NewDoQQueryHandler(),
	}

	kec, err = k.NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDoQParallelEventConsumer(config *k.KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaParallelConsumer, err error) {
	if config == nil {
		config = k.GetDefaultKafkaParallelConsumerConfig(DEFAULT_DOQ_CONSUMER_GROUP, k.DEFAULT_DOQ_TOPIC)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (k.EventConsumer, error) {
		return NewKafkaDoQEventConsumer(
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
