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

const DEFAULT_FINGERPRINT_CONSUMER_GROUP = "fingerprint-scan-group"

type SSHQueryHandler interface {
	Query(query *query.SSHQuery) (response *query.SSHResponse, err custom_errors.DoEErrors)
}

type DNSQueryHandler interface {
	Query(query *query.ConventionalDNSQuery) (response *query.ConventionalDNSResponse, err custom_errors.DoEErrors)
}

type FingerprintProcessEventHandler struct {
	EventProcessHandler

	DNSQueryHandler DNSQueryHandler
	SSHQueryHandler SSHQueryHandler
}

func (ph *FingerprintProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	fingerprintScan := &scan.FingerprintScan{}
	err := json.Unmarshal(msg.Value, fingerprintScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoT scan %s", err.Error())
		return err
	}

	// process
	fingerprintScan.Meta.SetStarted()

	// query SSH
	var qErr custom_errors.DoEErrors
	fingerprintScan.SSHResult, qErr = ph.SSHQueryHandler.Query(fingerprintScan.SSHQuery)
	if qErr != nil {
		fingerprintScan.Meta.AddError(qErr)
	}

	// query version bind
	fingerprintScan.VersionBindResult, qErr = ph.DNSQueryHandler.Query(fingerprintScan.VersionBindQuery)
	if qErr != nil {
		fingerprintScan.Meta.AddError(qErr)
	}

	// query version server
	fingerprintScan.VersionServerResult, qErr = ph.DNSQueryHandler.Query(fingerprintScan.VersionServerQuery)
	if qErr != nil {
		fingerprintScan.Meta.AddError(qErr)
	}

	fingerprintScan.Meta.SetFinished()

	// store
	err = storage.Store(fingerprintScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", fingerprintScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaFingerprintEventConsumer(
	config *KafkaConsumerConfig,
	storageHandler storage.StorageHandler,
	queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_FINGERPRINT_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &FingerprintProcessEventHandler{
			SSHQueryHandler: query.NewSSHQueryHandler(queryConfig),
			DNSQueryHandler: query.NewConventionalDNSQueryHandler(queryConfig),
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
