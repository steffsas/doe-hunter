package consumer

import (
	"encoding/json"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DOQ_CONSUMER_GROUP = "doq-scan-group"

type DoQQueryHandler interface {
	Query(query *query.DoQQuery) (response *query.DoQResponse, err custom_errors.DoEErrors)
}

type DoQProcessEventHandler struct {
	EventProcessHandler

	Producer     producer.ScanProducer
	QueryHandler DoQQueryHandler
}

func (ph *DoQProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	doqScan := &scan.DoQScan{}
	err = json.Unmarshal(msg.Value, doqScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoQ scan: %s", err.Error())
		return err
	}

	// process
	var qErr custom_errors.DoEErrors
	doqScan.Meta.SetStarted()
	doqScan.Result, qErr = ph.QueryHandler.Query(doqScan.Query)
	doqScan.Meta.SetFinished()
	if qErr != nil {
		doqScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoQ scan %s to %s:%d: %s", doqScan.Meta.ScanId, doqScan.Query.Host, doqScan.Query.Port, qErr.Error())
	}

	RedoDoEScanOnCertError(
		qErr,
		doqScan,
		scan.NewDoQScan(doqScan.Query, doqScan.Meta.ScanId, doqScan.Meta.RootScanId, doqScan.Meta.RunId),
		ph.Producer,
		k.DEFAULT_DOT_TOPIC,
	)

	// store
	err = storage.Store(doqScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", doqScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaDoQEventConsumer(
	config *KafkaConsumerConfig,
	prod producer.ScanProducer,
	storageHandler storage.StorageHandler,
	queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOQ_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		qh, err := query.NewDoQQueryHandler(queryConfig)
		if err != nil {
			logrus.Errorf("error creating DoQ query handler: %s", err.Error())
			return nil, err
		}
		return &DoQProcessEventHandler{
			Producer:     prod,
			QueryHandler: qh,
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
