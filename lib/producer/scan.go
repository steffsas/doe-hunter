package producer

import (
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/scan"
)

type ScanProducer struct {
	EventProducer

	Producer *KafkaEventProducer
	Config   *ProducerConfig
}

func (sp *ScanProducer) Produce(scan scan.Scan) (err error) {
	if sp.Producer == nil {
		return errors.New("producer not initialized")
	}

	logrus.Infof("produce scan %s to topic %s", scan.GetScanId(), sp.Config.Topic)

	var scanMsg []byte
	scanMsg, err = scan.Marshall()
	if err != nil {
		logrus.Errorf("failed to marshal scan: %v", err)
		return
	}

	err = sp.Producer.Produce(scanMsg, sp.Config.Topic, sp.Config.MaxPartitions)
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

func NewScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultCertificateScanProducerConfig()
	}

	p, err := NewKafkaProducer(&config.KafkaProducerConfig)
	if err != nil {
		logrus.Errorf("failed to create kafka producer: %v", err)
		return nil, err
	}

	return &ScanProducer{
		Producer: p,
		Config:   config,
	}, nil
}
