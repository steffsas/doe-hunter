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

const DEFAULT_DOT_CONSUMER_GROUP = "dot-scan-group"

type DoTProcessEventHandler struct {
	k.EventProcessHandler

	QueryHandler *query.DoTQueryHandler
}

func (ph *DoTProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	dotScan := &scan.DoTScan{}
	err := json.Unmarshal(msg.Value, dotScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoT scan %s: %s", dotScan.Meta.ScanId, err.Error())
		return err
	}

	// process
	var qErr custom_errors.DoEErrors
	dotScan.Meta.SetStarted()
	dotScan.Result, qErr = ph.QueryHandler.Query(dotScan.Query)
	dotScan.Meta.SetFinished()
	if qErr != nil {
		dotScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoT scan %s to %s:%d: %s", dotScan.Meta.ScanId, dotScan.Query.Host, dotScan.Query.Port, qErr.Error())
	}

	RedoDoEScanOnCertError(
		qErr,
		dotScan,
		scan.NewDoTScan(dotScan.Query, dotScan.Meta.ScanId, dotScan.Meta.RootScanId),
		k.DEFAULT_DOT_TOPIC,
	)

	// store
	err = storage.Store(dotScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", dotScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaDoTEventConsumer(config *k.KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOT_CONSUMER_GROUP
	}

	ph := &DoTProcessEventHandler{
		QueryHandler: query.NewDoTQueryHandler(),
	}

	kec, err = k.NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDoTParallelEventConsumer(config *k.KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaParallelConsumer, err error) {
	if config == nil {
		config = k.GetDefaultKafkaParallelConsumerConfig(DEFAULT_DOT_CONSUMER_GROUP, k.DEFAULT_DOT_TOPIC)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (k.EventConsumer, error) {
		return NewKafkaDoTEventConsumer(
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
