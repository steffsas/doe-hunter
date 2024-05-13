package producer

import (
	"errors"
	"math/rand"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

const DEFAULT_KAFKA_SERVER = "localhost:9092"
const DEFAULT_KAFKA_CONSUMER_GROUP = "default-consumer-group"
const DEFAULT_KAFKA_WRITE_TIMEOUT = 1000 * time.Millisecond

type EventProducer interface {
	Produce(msg []byte) (err error)
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

func (kep *KafkaEventProducer) Produce(msg []byte, topic string, partitions int) (err error) {
	if kep.Producer == nil {
		return errors.New("producer not initialized")
	}

	if partitions <= 0 {
		return errors.New("invalid partition count")
	}

	if topic == "" {
		return errors.New("invalid topic")
	}

	if len(msg) == 0 {
		return errors.New("message should not be empty")
	}

	randomPartition := rand.Int() % partitions

	err = kep.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: int32(randomPartition)},
		Value:          msg,
	}, nil)

	return
}

func (kep *KafkaEventProducer) Close() {
	if kep.Producer != nil {
		kep.Producer.Close()
	}
}

func NewKafkaProducer(config *KafkaProducerConfig) (kp *KafkaEventProducer, err error) {
	if config == nil {
		config = GetDefaultKafkaProducerConfig()
	}

	if config.Server == "" {
		return nil, errors.New("invalid kafka server")
	}

	if config.Timeout <= 0 {
		return nil, errors.New("invalid timeout")
	}

	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":  config.Server,
		"message.timeout.ms": int(config.Timeout.Milliseconds()),
		"acks":               "1",
	})
	if err != nil {
		return nil, err
	}

	return &KafkaEventProducer{
		Config:   config,
		Producer: p,
	}, nil
}

type KafkaProducerConfig struct {
	Server  string
	Timeout time.Duration
	Acks    string
}

func GetDefaultKafkaProducerConfig() *KafkaProducerConfig {
	return &KafkaProducerConfig{
		Server:  DEFAULT_KAFKA_SERVER,
		Timeout: DEFAULT_KAFKA_WRITE_TIMEOUT,
		Acks:    "1",
	}
}
