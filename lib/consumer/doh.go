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

const DEFAULT_DOH_CONSUMER_TOPIC = "doh-scan"
const DEFAULT_DOH_CONSUMER_GROUP = "doh-scan-group"
const DEFAULT_DOH_CONCURRENT_CONSUMER = 10

type DoHProcessEventHandler struct {
	EventProcessHandler

	QueryHandler *query.DoHQueryHandler
}

func (ph *DoHProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	// unmarshal message
	dohScan := &scan.DoHScan{}
	err = json.Unmarshal(msg.Value, dohScan)
	if err != nil {
		return err
	}

	// process
	dohScan.Result, err = ph.QueryHandler.Query(dohScan.Query)
	if err != nil {
		dohScan.Meta.AddError(err)
		logrus.Errorf("error processing DoH scan %s: %s", dohScan.Meta.ScanId, err)
	}

	if helper.IsCertificateError(err) {
		logrus.Warnf("DoH scan %s: reschedule without cert verification because of certificate error: %s", dohScan.Meta.ScanId, err)

		newDoHScan := scan.NewDoHScan(dohScan.Query, dohScan.Meta.ParentScanId, dohScan.Meta.ScanId)
		newDoHScan.Query.SkipCertificateVerify = true

		dohProducer, err := producer.NewDoHScanProducer(nil)
		if err != nil {
			logrus.Errorf("error creating DoH scan producer: %s", err)
			dohScan.Meta.AddError(err)
		} else {
			err = dohProducer.Produce(newDoHScan)
			if err != nil {
				logrus.Errorf("error rescheduling DoH scan %s: %s", dohScan.Meta.ScanId, err)
				dohScan.Meta.AddError(err)
			}
		}
	}

	// schedule certificate scan
	certQuery := query.NewCertificateQuery()
	certQuery.Host = dohScan.Query.Host
	certQuery.Port = dohScan.Query.Port
	certQuery.SkipCertificateVerify = dohScan.Query.SkipCertificateVerify

	scanCert := scan.NewCertificateScan(certQuery, dohScan.Meta.RootScanId, dohScan.Meta.ScanId)
	certProducer, err := producer.NewCertificateScanProducer(nil)
	if err != nil {
		logrus.Errorf("error creating cert scan producer: %s", err)
		dohScan.Meta.AddError(err)
	} else {
		err = certProducer.Produce(scanCert)
		if err != nil {
			logrus.Errorf("error scheduling cert scan %s: %s", dohScan.Meta.ScanId, err)
			dohScan.Meta.AddError(err)
		}
	}

	// store
	err = storage.Store(dohScan)

	return
}

func NewKafkaDoHEventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DOH_CONSUMER_GROUP
	}

	ph := &DoHProcessEventHandler{
		QueryHandler: query.NewDoHQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDoHParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DOH_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: &KafkaConsumerConfig{
				ConsumerGroup: DEFAULT_DOH_CONSUMER_GROUP,
				Server:        DEFAULT_KAFKA_SERVER,
			},
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if config.KafkaConsumerConfig == nil {
		config.KafkaConsumerConfig = &KafkaConsumerConfig{
			ConsumerGroup: DEFAULT_DOH_CONSUMER_GROUP,
			Server:        DEFAULT_KAFKA_SERVER,
		}
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaDoHEventConsumer(
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
