package consumer

import (
	"encoding/json"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

type CertificateQueryHandler interface {
	Query(query *query.CertificateQuery) (response *query.CertificateResponse, err custom_errors.DoEErrors)
}

const DEFAULT_CERTIFICATE_CONSUMER_GROUP = "certificate-scan-group"

type CertificateProcessEventHandler struct {
	EventProcessHandler

	QueryHandler CertificateQueryHandler
}

func (ph *CertificateProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	certificateScan := &scan.CertificateScan{}
	umErr := json.Unmarshal(msg.Value, certificateScan)
	if umErr != nil {
		logrus.Errorf("error unmarshalling certificate scan: %s", umErr)
		return umErr
	}

	// process
	var qErr custom_errors.DoEErrors
	certificateScan.Meta.SetStarted()
	certificateScan.Result, qErr = ph.QueryHandler.Query(certificateScan.Query)
	certificateScan.Meta.SetFinished()
	if qErr != nil {
		logrus.Errorf("error processing certificate scan %s to %s:%d: %s", certificateScan.Meta.ScanId, certificateScan.Query.Host, certificateScan.Query.Port, qErr.Error())
		certificateScan.Meta.AddError(qErr)
	}

	// store
	err := storage.Store(certificateScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", certificateScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaCertificateEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler, queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_CERTIFICATE_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		qh, err := query.NewCertificateQueryHandler(queryConfig)
		if err != nil {
			return nil, err
		}

		return &CertificateProcessEventHandler{
			QueryHandler: qh,
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
