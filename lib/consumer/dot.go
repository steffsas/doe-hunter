package consumer

import (
	"encoding/json"
	"errors"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DOT_CONSUMER_TOPIC = "dot-scan"
const DEFAULT_DOT_CONSUMER_GROUP = "dot-scan-group"
const DEFAULT_DOT_CONCURRENT_CONSUMER = 10

type DoTProcessEventHandler struct {
	EventProcessHandler

	QueryHandler *query.DoTQueryHandler
}

func (ph *DoTProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	dotScan := &scan.DoTScan{}
	err = json.Unmarshal(msg.Value, dotScan)
	if err != nil {
		return err
	}

	// process
	dotScan.Result, err = ph.QueryHandler.Query(dotScan.Query)
	if err != nil {
		dotScan.Meta.AddError(err)
		logrus.Errorf("error processing DoH scan %s: %s", dotScan.Meta.ScanId, err)
	}

	if helper.IsCertificateError(err) {
		logrus.Warnf("DoH scan %s: reschedule without cert verification because of certificate error: %s", dotScan.Meta.ScanId, err)

		newDoTScan := scan.NewDoTScan(dotScan.Query, dotScan.Meta.ParentScanId, dotScan.Meta.ScanId)
		newDoTScan.Query.SkipCertificateVerify = true

		dotProducer, err := producer.NewDoTScanProducer(nil)
		if err != nil {
			logrus.Errorf("error creating DoH scan producer: %s", err)
			dotScan.Meta.AddError(err)
		} else {
			err = dotProducer.Produce(newDoTScan)
			if err != nil {
				logrus.Errorf("error rescheduling DoH scan %s: %s", dotScan.Meta.ScanId, err)
				dotScan.Meta.AddError(err)
			}
		}
	}

	// store
	err = storage.Store(dotScan)

	return
}

func NewKafkaDoTEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOT_CONSUMER_GROUP
	}

	ph := &DoTProcessEventHandler{
		QueryHandler: query.NewDoTQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDoTParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DOT_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: &KafkaConsumerConfig{
				ConsumerGroup: DEFAULT_DOT_CONSUMER_GROUP,
				Server:        DEFAULT_KAFKA_SERVER,
			},
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if config.KafkaConsumerConfig == nil {
		config.KafkaConsumerConfig = &KafkaConsumerConfig{
			ConsumerGroup: DEFAULT_DOT_CONSUMER_GROUP,
			Server:        DEFAULT_KAFKA_SERVER,
		}
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaDoTEventConsumer(
			config.KafkaConsumerConfig,
			storageHandler,
		)
	}
	kec, err = NewKafkaParallelEventConsumer(createConsumerFunc, config.KafkaParallelEventConsumerConfig)

	if err != nil {
		logrus.Errorf("failed to create parallel consumer: %v", err)
	}

	return
}
