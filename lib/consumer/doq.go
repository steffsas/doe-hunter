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

const DEFAULT_DOQ_CONSUMER_TOPIC = "doq-scan"
const DEFAULT_DOQ_CONSUMER_GROUP = "doq-scan-group"
const DEFAULT_DOQ_CONCURRENT_CONSUMER = 10

type DoQProcessEventHandler struct {
	EventProcessHandler

	QueryHandler *query.DoQQueryHandler
}

func (ph *DoQProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	doqScan := &scan.DoQScan{}
	err = json.Unmarshal(msg.Value, doqScan)
	if err != nil {
		return err
	}

	// process
	doqScan.Result, err = ph.QueryHandler.Query(doqScan.Query)
	if err != nil {
		doqScan.Meta.AddError(err)
		logrus.Errorf("error processing DoH scan %s: %s", doqScan.Meta.ScanId, err)
	}

	if helper.IsCertificateError(err) {
		logrus.Warnf("DoH scan %s: reschedule without cert verification because of certificate error: %s", doqScan.Meta.ScanId, err)

		newDoQScan := scan.NewDoQScan(doqScan.Query, doqScan.Meta.ParentScanId, doqScan.Meta.ScanId)
		newDoQScan.Query.SkipCertificateVerify = true

		doqProducer, err := producer.NewDoQScanProducer(nil)
		if err != nil {
			logrus.Errorf("error creating DoH scan producer: %s", err)
			doqScan.Meta.AddError(err)
		} else {
			err = doqProducer.Produce(newDoQScan)
			if err != nil {
				logrus.Errorf("error rescheduling DoH scan %s: %s", doqScan.Meta.ScanId, err)
				doqScan.Meta.AddError(err)
			}
		}
	}

	// store
	err = storage.Store(doqScan)

	return
}

func NewKafkaDoQEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOQ_CONSUMER_GROUP
	}

	ph := &DoQProcessEventHandler{
		QueryHandler: query.NewDoQQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDoQParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DOQ_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: &KafkaConsumerConfig{
				ConsumerGroup: DEFAULT_DOQ_CONSUMER_GROUP,
				Server:        DEFAULT_KAFKA_SERVER,
			},
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if config.KafkaConsumerConfig == nil {
		config.KafkaConsumerConfig = &KafkaConsumerConfig{
			ConsumerGroup: DEFAULT_DOH_CONSUMER_GROUP,
			Server:        DEFAULT_KAFKA_SERVER,
		}
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaDoQEventConsumer(
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
