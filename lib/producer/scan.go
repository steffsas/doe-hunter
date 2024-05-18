package producer

import (
	"errors"

	k "github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/scan"
)

type ScanProducer struct {
	kafka.EventProducer

	Producer *KafkaEventProducer
	Config   *KafkaProducerConfig
}

func (sp *ScanProducer) Produce(scan scan.Scan) (err error) {
	if sp.Producer == nil {
		return errors.New("producer not initialized")
	}

	var scanMsg []byte
	scanMsg, err = scan.Marshall()
	if err != nil {
		logrus.Errorf("failed to marshal scan: %v", err)
		return
	}

	return sp.Producer.Produce(scanMsg)
}

func (sp *ScanProducer) Close() {
	if sp.Producer != nil {
		sp.Producer.Close()
	}
}

func (sp *ScanProducer) Flush(timeout int) int {
	if sp.Producer == nil {
		return 0
	}

	return sp.Producer.Flush(timeout)
}

func (sp *ScanProducer) Events() chan k.Event {
	if sp.Producer == nil {
		return nil
	}

	return sp.Producer.Events()
}

func NewScanProducer(topic string, config *KafkaProducerConfig) (sp *ScanProducer, err error) {
	if topic == "" {
		return nil, errors.New("invalid topic")
	}

	p, err := NewKafkaProducer(topic, config)
	if err != nil {
		logrus.Errorf("failed to create kafka producer: %v", err)
		return nil, err
	}

	return &ScanProducer{
		Producer: p,
		Config:   config,
	}, nil
}
