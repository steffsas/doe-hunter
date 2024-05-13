package producer

import (
	"encoding/json"
	"errors"

	"github.com/steffsas/doe-hunter/lib/scan"
)

const DEFAULT_DOH_TOPIC = "doh-scan"

type DoHProducerConfig struct {
	KafkaProducerConfig

	Topic         string
	MaxPartitions int
}

type DoHProducer struct {
	EventProducer

	Producer *KafkaEventProducer
	Config   *DoHProducerConfig
}

func (dp *DoHProducer) Produce(scan *scan.DoTScan) (err error) {
	if dp.Producer == nil {
		return errors.New("producer not initialized")
	}

	if scan == nil {
		return errors.New("scan is nil")
	}

	if scan.Query == nil {
		return errors.New("query is nil")
	}

	if scan.Meta == nil {
		return errors.New("meta is nil")
	}

	var scanMsg []byte
	scanMsg, err = json.Marshal(scan)
	if err != nil {
		return
	}

	err = dp.Producer.Produce(scanMsg, dp.Config.Topic, dp.Config.MaxPartitions)

	return
}
