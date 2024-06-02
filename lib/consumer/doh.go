package consumer

import (
	"encoding/json"

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
	EventProcessHandler

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
		scan.NewDoHScan(dohScan.Query, dohScan.Meta.ScanId, dohScan.Meta.RootScanId, dohScan.Meta.RunId),
		k.DEFAULT_DOT_TOPIC,
	)

	// store
	err = storage.Store(dohScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", dohScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaDoHEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler, queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOH_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		qh, err := query.NewDoHQueryHandler(queryConfig)
		if err != nil {
			return nil, err
		}
		return &DoHProcessEventHandler{
			QueryHandler: qh,
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
