package kafka

import (
	"time"

	"github.com/confluentinc/confluent-kafka-go/kafka"
)

type EventProducer interface {
	Produce(msg []byte) (err error)
	Close()
}

type KafkaProducerConfig struct {
	Server  string
	Timeout time.Duration
	Acks    string

	Topic             string
	MaxPartitions     int
	ReplicationFactor int
}

type KafkaProducer interface {
	Produce(msg *kafka.Message, deliveryChan chan kafka.Event) (err error)
	Close()
}

type KafkaEventProducer struct {
	EventProducer

	Config *KafkaProducerConfig

	Producer KafkaProducer
}
