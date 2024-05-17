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

const DEFAULT_CERTIFICATE_CONSUMER_GROUP = "certificate-scan-group"

type CertificateProcessEventHandler struct {
	k.EventProcessHandler

	QueryHandler *query.CertificateQueryHandler
}

func (ph *CertificateProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	certificateScan := &scan.CertificateScan{}
	umErr := json.Unmarshal(msg.Value, certificateScan)
	if umErr != nil {
		logrus.Errorf("error unmarshalling DoH scan: %s", umErr)
		return umErr
	}

	// process
	var qErr custom_errors.DoEErrors
	certificateScan.Meta.SetStarted()
	certificateScan.Result, qErr = ph.QueryHandler.Query(certificateScan.Query)
	certificateScan.Meta.SetFinished()
	if qErr != nil {
		logrus.Errorf("error processing DoH scan %s: %s", certificateScan.Meta.ScanId, qErr.Error())
		certificateScan.Meta.AddError(qErr)
	}

	// store
	err := storage.Store(certificateScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", certificateScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaCertificateEventConsumer(config *k.KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_CERTIFICATE_CONSUMER_GROUP
	}

	ph := &CertificateProcessEventHandler{
		QueryHandler: query.NewCertificateQueryHandler(),
	}

	kec, err = k.NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaCertificateParallelEventConsumer(config *k.KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaParallelConsumer, err error) {
	if config == nil {
		config = k.GetDefaultKafkaParallelConsumerConfig(DEFAULT_CERTIFICATE_CONSUMER_GROUP, k.DEFAULT_CERTIFICATE_TOPIC)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (k.EventConsumer, error) {
		return NewKafkaCertificateEventConsumer(
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
