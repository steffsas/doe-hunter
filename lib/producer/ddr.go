package producer

const DEFAULT_DDR_TOPIC = "ddr-scan"
const DEFAULT_DDR_PARTITIONS = 100

func NewDefaultDDRScanProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_DDR_TOPIC,
		MaxPartitions:       DEFAULT_DDR_PARTITIONS,
	}
}

func NewDDRScanProducer(config *ProducerConfig) (sp *ScanProducer, err error) {
	if config == nil {
		config = NewDefaultDDRScanProducerConfig()
	}

	return NewScanProducer(config)
}
