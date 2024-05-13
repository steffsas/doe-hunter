package consumer

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DDR_CONSUMER_TOPIC = "ddr-scan"
const DEFAULT_DDR_CONSUMER_GROUP = "ddr-scan-group"
const DEFAULT_DDR_CONCURRENT_CONSUMER = 10

type DDRProcessEventHandler struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (ddr *DDRProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	if msg == nil {
		logrus.Warn("received nil message, nothing to consume")
		return nil
	}

	scan := &scan.DDRScan{}
	err = json.Unmarshal(msg.Value, scan)
	if err != nil {
		logrus.Errorf("failed to unmarshal message into %s", reflect.TypeOf(scan).String())
		return
	}

	logrus.Infof("received DDR scan %s of host %s with port %d", scan.Meta.ScanID, scan.Query.Host, scan.Query.Port)

	// execute query
	scan.Meta.SetStarted()
	scan.Result, err = ddr.QueryHandler.Query(scan.Query)
	scan.Meta.SetFinished()

	if err != nil {
		logrus.Errorf("failed to query %s: %v", scan.Meta.ScanID, err)
		scan.Meta.Errors = append(scan.Meta.Errors, err)

		// if certificate error, retry without certificate verification
		// TODO retry on certificate error
		logrus.Infof("scheduling scan again without certificate verification %s --> TBD", scan.Meta.ScanID)
	} else {
		logrus.Infof(
			"successfully queried %s on host %s with port %d, received %d SVCB records",
			scan.Meta.ScanID,
			scan.Query.Host,
			scan.Query.Port,
			len(scan.Result.Response.ResponseMsg.Answer),
		)

		// TODO schedule certificate scan

		// TODO schedule DoE scans
		logrus.Infof("scheduling DoE scans for %s --> TBD", scan.Meta.ScanID)
	}

	err = storage.Store(scan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", scan.Meta.ScanID, err)
	}

	return
}

func NewKafkaDDREventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DDR_CONSUMER_GROUP
	}

	ph := &DDRProcessEventHandler{
		QueryHandler: query.NewConventionalDNSQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDDRParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DDR_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: GetDefaultKafkaConsumerConfig(),
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaDDREventConsumer(
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
