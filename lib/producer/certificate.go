package producer

import (
	"encoding/json"
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
)

const DEFAULT_CERTIFICATE_TOPIC = "certificates"
const DEFAULT_CERTIFICATE_PARTITIONS = 100

type CertificateProducer struct {
	EventProducer

	Producer *KafkaEventProducer
	Config   *ProducerConfig
}

func (cp *CertificateProducer) Produce(query *query.CertificateQuery, rootScanID string, parentScanID string) (err error) {
	if cp.Producer == nil {
		return errors.New("producer not initialized")
	}

	scan := &scan.CertificateScan{
		Meta: &scan.CertificateScanMetaInformation{
			ScanMetaInformation: scan.ScanMetaInformation{
				Errors:       []error{},
				ParentScanID: parentScanID,
				RootScanID:   rootScanID,
			},
		},
		Query: query,
	}

	scan.Meta.GenerateScanID()
	scan.Meta.SetScheduled()

	logrus.Infof("create certificate scan for host %s on port %d", scan.Query.Host, scan.Query.Port)

	var scanMsg []byte
	if scanMsg, err = json.Marshal(scan); err != nil {
		logrus.Errorf("failed to marshal scan: %v", err)
		return
	}

	if err = cp.Producer.Produce(scanMsg, cp.Config.Topic, DEFAULT_DDR_PARTITIONS); err != nil {
		logrus.Errorf("failed to produce scan: %v", err)
		return
	}

	return
}

func (cp *CertificateProducer) Close() {
	if cp.Producer != nil {
		cp.Producer.Close()
	}
}

func NewDefaultCertificateProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_CERTIFICATE_TOPIC,
		MaxPartitions:       DEFAULT_CERTIFICATE_PARTITIONS,
	}
}

func NewCertificateProducer(config *ProducerConfig) (cp *CertificateProducer, err error) {
	if config == nil {
		config = NewDefaultCertificateProducerConfig()
	}

	if config.MaxPartitions <= 0 {
		config.MaxPartitions = DEFAULT_CERTIFICATE_PARTITIONS
	}

	if config.Topic == "" {
		config.Topic = DEFAULT_CERTIFICATE_TOPIC
	}

	p, err := NewKafkaProducer(&config.KafkaProducerConfig)
	if err != nil {
		logrus.Errorf("failed to create kafka producer: %v", err)
		return nil, err
	}

	return &CertificateProducer{
		Config:   config,
		Producer: p,
	}, nil
}
