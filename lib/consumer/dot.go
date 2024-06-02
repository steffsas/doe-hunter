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

const DEFAULT_DOT_CONSUMER_GROUP = "dot-scan-group"

type DoTQueryHandler interface {
	Query(query *query.DoTQuery) (response *query.DoTResponse, err custom_errors.DoEErrors)
}

type DoTProcessEventHandler struct {
	EventProcessHandler

	QueryHandler DoTQueryHandler
}

func (ph *DoTProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	// unmarshal message
	dotScan := &scan.DoTScan{}
	err := json.Unmarshal(msg.Value, dotScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DoT scan %s", err.Error())
		return err
	}

	// process
	var qErr custom_errors.DoEErrors
	dotScan.Meta.SetStarted()
	dotScan.Result, qErr = ph.QueryHandler.Query(dotScan.Query)
	dotScan.Meta.SetFinished()
	if qErr != nil {
		dotScan.Meta.AddError(qErr)
		logrus.Errorf("error processing DoT scan %s to %s:%d: %s", dotScan.Meta.ScanId, dotScan.Query.Host, dotScan.Query.Port, qErr.Error())
	}

	RedoDoEScanOnCertError(
		qErr,
		dotScan,
		scan.NewDoTScan(dotScan.Query, dotScan.Meta.ScanId, dotScan.Meta.RootScanId, dotScan.Meta.RunId),
		k.DEFAULT_DOT_TOPIC,
	)

	// store
	err = storage.Store(dotScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", dotScan.Meta.ScanId, err)
	}
	return err
}

func NewKafkaDoTEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler, queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOT_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &DoTProcessEventHandler{
			QueryHandler: query.NewDoTQueryHandler(queryConfig),
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
