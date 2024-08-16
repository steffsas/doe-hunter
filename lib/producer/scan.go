package producer

import (
	"errors"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/scan"
)

// TODO rename interfaces to unofficial naming convention https://www.reddit.com/r/golang/comments/cjrk46/is_there_a_naming_convention_for_interface_struct/
type ScanProducer interface {
	Produce(scan scan.Scan, topic string) error
	Close()
	Flush(timeout int) int
	Events() chan kafka.Event
	WatchEvents()
}

type KafkaScanProducer struct {
	ScanProducer

	Producer EventProducer
}

func (sp *KafkaScanProducer) Produce(scan scan.Scan, topic string) (err error) {
	if sp.Producer == nil {
		return errors.New("producer not initialized")
	}

	var scanMsg []byte
	scanMsg, err = scan.Marshall()
	if err != nil {
		logrus.Errorf("failed to marshal scan: %v", err)
		return
	}

	return sp.Producer.Produce(scanMsg, topic)
}

func (sp *KafkaScanProducer) Close() {
	if sp.Producer != nil {
		sp.Producer.Close()
	}
}

func (sp *KafkaScanProducer) Flush(timeout int) int {
	if sp.Producer == nil {
		return 0
	}

	return sp.Producer.Flush(timeout)
}

func (sp *KafkaScanProducer) Events() chan kafka.Event {
	if sp.Producer == nil {
		return nil
	}

	return sp.Producer.Events()
}

func NewScanProducer(eventProducer EventProducer) (sp ScanProducer, err error) {
	return &KafkaScanProducer{
		Producer: eventProducer,
	}, nil
}

func NewKafkaScanProducer(config *KafkaProducerConfig) (sp ScanProducer, err error) {
	if config == nil {
		return nil, errors.New("invalid kafka producer config")
	}

	ep, err := NewKafkaProducer(config)
	if err != nil {
		return nil, err
	}

	return NewScanProducer(ep)
}
