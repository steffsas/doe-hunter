package producer

const DEFAULT_DOT_TOPIC = "dot-scan"
const DEFAULT_DOT_PARTITIONS = 100

func NewDefaultDoTProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_DOT_TOPIC,
		MaxPartitions:       DEFAULT_DOT_PARTITIONS,
	}
}

func NewDoTScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultDoTProducerConfig()
	}

	return NewScanProducer(config)
}
