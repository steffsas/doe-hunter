package producer

const DEFAULT_DOQ_TOPIC = "doq-scan"
const DEFAULT_DOQ_PARTITIONS = 100

func NewDefaultDoQProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_DOQ_TOPIC,
		MaxPartitions:       DEFAULT_DOQ_PARTITIONS,
	}
}

func NewDoQScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultDoQProducerConfig()
	}

	return NewScanProducer(config)
}
