package producer

const DEFAULT_DOH_TOPIC = "doh-scan"
const DEFAULT_DOH_PARTITIONS = 100

func NewDefaultDoHScanProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_DOH_TOPIC,
		MaxPartitions:       DEFAULT_DOH_PARTITIONS,
	}
}

func NewDoHScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultDoHScanProducerConfig()
	}

	return NewScanProducer(config)
}
