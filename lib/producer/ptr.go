package producer

const DEFAULT_PTR_TOPIC = "ptr-scan"
const DEFAULT_PTR_PARTITIONS = 100

func NewDefaultPTRProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_PTR_TOPIC,
		MaxPartitions:       DEFAULT_PTR_PARTITIONS,
	}
}

func NewPTRScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultPTRProducerConfig()
	}

	return NewScanProducer(config)
}
