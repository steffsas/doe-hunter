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

const DEFAULT_DDR_CONSUME_TOPIC = "ddr-scan"
const DEFAULT_DDR_CONSUME_GROUP = "ddr-scan-group"
const DEFAULT_DDR_CONCURRENT_CONSUMER = 10

type DDRScanConsumeHandler struct {
	EventProcessHandler
}

func (ddr *DDRScanConsumeHandler) Consume(msg *kafka.Message, storage storage.StorageHandler) {
	if msg == nil {
		logrus.Warn("received nil message, nothing to consume")
		return
	}

	scan := &scan.DDRScan{}
	err := json.Unmarshal(msg.Value, scan)
	if err != nil {
		logrus.Errorf("failed to unmarshal message into %s", reflect.TypeOf(scan).String())
		return
	}

	logrus.Infof("received DDR scan %s of host %s with port %d", scan.Meta.ScanID, scan.Scan.Host, scan.Scan.Port)

	// prepare query
	qh := query.NewDDRQueryHandler()
	qh.QueryObj = scan.Scan

	// execute query
	scan.Meta.SetStarted()
	res, err := qh.Query()
	scan.Meta.SetFinished()

	scan.Result = *res

	if err != nil {
		logrus.Errorf("failed to query %s: %v", scan.Meta.ScanID, err)
		scan.Meta.Errors = append(scan.Meta.Errors, err)
	} else {
		logrus.Infof("successfully queried %s on host %s with port %d, received %d SVCB records", scan.Meta.ScanID, scan.Scan.Host, scan.Scan.Port, len(scan.Result.ResponseMsg.Answer))

		// schedule DoE scans
		logrus.Infof("scheduling DoE scans for %s --> TBD", scan.Meta.ScanID)
	}
}

func NewKafkaDDREventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DDR_CONSUME_GROUP
	}

	ph := &DDRScanConsumeHandler{}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDDRParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DDR_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: KafkaConsumerConfig{
				Server:        DEFAULT_KAFKA_SERVER,
				ConsumerGroup: DEFAULT_DDR_CONSUME_GROUP,
			},
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaDDREventConsumer(&config.KafkaConsumerConfig, storageHandler)
	}
	kec, err = NewKafkaParallelEventConsumer(createConsumerFunc, &config.KafkaParallelEventConsumerConfig)

	if err != nil {
		logrus.Errorf("failed to create parallel consumer: %v", err)
	}

	return
}
