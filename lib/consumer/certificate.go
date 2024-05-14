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

const DEFAULT_CERTIFICATE_CONSUMER_TOPIC = "certificate-scan"
const DEFAULT_CERTIFICATE_CONSUMER_GROUP = "certificate-scan-group"
const DEFAULT_CERTIFICATE_CONCURRENT_CONSUMER = 10

type CertificateProcessEventHandler struct {
	EventProcessHandler

	QueryHandler *query.CertificateQueryHandler
}

func (ph *CertificateProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	certificateScan := &scan.CertificateScan{}
	err = json.Unmarshal(msg.Value, certificateScan)
	if err != nil {
		return err
	}

	// process
	certificateScan.Result, err = ph.QueryHandler.Query(certificateScan.Query)
	if err != nil {
		logrus.Errorf("error processing DoH scan %s: %s", certificateScan.Meta.ScanId, err)
		certificateScan.Meta.AddError(err)
	}

	if helper.IsCertificateError(err) {
		logrus.Warnf("DoH scan %s: reschedule without cert verification because of certificate error: %s", certificateScan.Meta.ScanId, err)

		newCertScan := scan.NewCertificateScan(certificateScan.Query, certificateScan.Meta.ParentScanId, certificateScan.Meta.ScanId)
		newCertScan.Query.SkipCertificateVerify = true

		certProducer, err := producer.NewCertificateScanProducer(nil)
		if err != nil {
			logrus.Errorf("error creating DoH scan producer: %s", err)
			certificateScan.Meta.AddError(err)
		} else {
			err = certProducer.Produce(newCertScan)
			if err != nil {
				logrus.Errorf("error rescheduling DoH scan %s: %s", certificateScan.Meta.ScanId, err)
				certificateScan.Meta.AddError(err)
			}
		}
	}

	// store
	err = storage.Store(certificateScan)

	return
}

func NewKafkaCertificateEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_CERTIFICATE_CONSUMER_GROUP
	}

	ph := &CertificateProcessEventHandler{
		QueryHandler: query.NewCertificateQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaCertificateParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DOT_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: &KafkaConsumerConfig{
				ConsumerGroup: DEFAULT_CERTIFICATE_CONSUMER_GROUP,
				Server:        DEFAULT_KAFKA_SERVER,
			},
		}
		config.KafkaConsumerConfig.ConsumerGroup = DEFAULT_CERTIFICATE_CONSUMER_GROUP
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if config.KafkaConsumerConfig == nil {
		config.KafkaConsumerConfig = &KafkaConsumerConfig{
			ConsumerGroup: DEFAULT_CERTIFICATE_CONSUMER_GROUP,
			Server:        DEFAULT_KAFKA_SERVER,
		}
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaCertificateEventConsumer(
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
