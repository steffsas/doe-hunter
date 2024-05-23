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

const DEFAULT_DOH_CONSUMER_GROUP = "doh-scan-group"

type DoHQueryHandler interface {
	Query(query *query.DoHQuery) (response *query.DoHResponse, err custom_errors.DoEErrors)
}

type DoHProcessEventHandler struct {
	k.EventProcessHandler

	QueryHandler DoHQueryHandler
}

func (ph *DoHProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	dohScan := &scan.DoHScan{}
	err := json.Unmarshal(msg.Value, dohScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoH scan: %s", err.Error())
		return err
	}

	// process
	var qErr custom_errors.DoEErrors
	dohScan.Meta.SetStarted()
	dohScan.Result, qErr = ph.QueryHandler.Query(dohScan.Query)
	dohScan.Meta.SetFinished()
	if qErr != nil {
		dohScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoH scan %s to %s:%d with URI %s: %s", dohScan.Meta.ScanId, dohScan.Query.Host, dohScan.Query.Port, dohScan.Query.URI, qErr.Error())
	}

	RedoDoEScanOnCertError(
		qErr,
		dohScan,
		scan.NewDoHScan(dohScan.Query, dohScan.Meta.ScanId, dohScan.Meta.RootScanId),
		k.DEFAULT_DOT_TOPIC,
	)

	// store
	err = storage.Store(dohScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", dohScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaDoHEventConsumer(config *k.KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOH_CONSUMER_GROUP
	}

	ph := &DoHProcessEventHandler{
		QueryHandler: query.NewDoHQueryHandler(),
	}

	kec, err = k.NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDoHParallelEventConsumer(config *k.KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaParallelConsumer, err error) {
	if config == nil {
		config = k.GetDefaultKafkaParallelConsumerConfig(DEFAULT_DOH_CONSUMER_GROUP, k.DEFAULT_DOH_TOPIC)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (k.EventConsumer, error) {
		return NewKafkaDoHEventConsumer(
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
