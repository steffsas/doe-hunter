package producer

const DEFAULT_CERTIFICATE_TOPIC = "certificate-scan"
const DEFAULT_CERTIFICATE_PARTITIONS = 100

func NewDefaultCertificateScanProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_CERTIFICATE_TOPIC,
		MaxPartitions:       DEFAULT_CERTIFICATE_PARTITIONS,
	}
}

func NewCertificateScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultCertificateScanProducerConfig()
	}

	return NewScanProducer(config)
}
