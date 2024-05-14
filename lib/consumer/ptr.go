package consumer

import (
	"encoding/json"
	"errors"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_PTR_CONSUMER_TOPIC = "ptr-scan"
const DEFAULT_PTR_CONSUMER_GROUP = "ptr-scan-group"
const DEFAULT_PTR_CONCURRENT_CONSUMER = 10

type PTRProcessEventHandler struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (ph *PTRProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	ptrScan := &scan.PTRScan{}
	err = json.Unmarshal(msg.Value, ptrScan)
	if err != nil {
		return err
	}

	// process
	ptrScan.Result, err = ph.QueryHandler.Query(ptrScan.Query)
	if err != nil {
		ptrScan.Meta.AddError(err)
		logrus.Errorf("error processing PTR scan %s: %s", ptrScan.Meta.ScanId, err)
	}

	// store
	err = storage.Store(ptrScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", ptrScan.Meta.ScanId, err)
	}
	return
}

func NewKafkaPTREventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_PTR_CONSUMER_GROUP
	}

	ph := &PTRProcessEventHandler{
		QueryHandler: query.NewPTRQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaPTRParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_PTR_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: &KafkaConsumerConfig{
				ConsumerGroup: DEFAULT_PTR_CONSUMER_GROUP,
				Server:        DEFAULT_KAFKA_SERVER,
			},
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if config.KafkaConsumerConfig == nil {
		config.KafkaConsumerConfig = &KafkaConsumerConfig{
			ConsumerGroup: DEFAULT_PTR_CONSUMER_GROUP,
			Server:        DEFAULT_KAFKA_SERVER,
		}
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaPTREventConsumer(
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
