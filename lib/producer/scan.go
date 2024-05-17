package producer

import (
	"errors"

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

	logrus.Infof("produce scan %s to topic %s", scan.GetMetaInformation().ScanId, sp.Producer.Topic)

	var scanMsg []byte
	scanMsg, err = scan.Marshall()
	if err != nil {
		logrus.Errorf("failed to marshal scan: %v", err)
		return
	}

	err = sp.Producer.Produce(scanMsg)
	if err != nil {
		logrus.Errorf("failed to produce scan: %v", err)
	}

	return
}

func (sp *ScanProducer) Close() {
	if sp.Producer != nil {
		sp.Producer.Close()
	}
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
