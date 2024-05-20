package producer

import (
	"errors"
	"math/rand"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	k "github.com/steffsas/doe-hunter/lib/kafka"
)

const DEFAULT_KAFKA_SERVER = "localhost:29092"
const DEFAULT_ACKS = "1"
const DEFAULT_KAFKA_WRITE_TIMEOUT = 10000 * time.Millisecond
const DEFAULT_FLUSH_TIMEOUT_MS = 5000
const DEFAULT_MAX_PARTITIONS int32 = 100

type KafkaProducerConfig struct {
	Server  string
	Timeout time.Duration
	Acks    string

	MaxPartitions     int32
	ReplicationFactor int
}

type KafkaEventProducerI interface {
	k.EventProducer

	Events() chan kafka.Event
	Flush(timeout int) int
}

type KafkaProducer interface {
	Produce(msg *kafka.Message, deliveryChan chan kafka.Event) (err error)
	Flush(timeout int) int
	Events() chan kafka.Event
	Close()
}

type KafkaEventProducer struct {
	KafkaEventProducerI

	Config   *KafkaProducerConfig
	Topic    string
	Producer KafkaProducer
}

// blocking call to produce a message
func (kep *KafkaEventProducer) Produce(msg []byte) (err error) {
	if kep.Producer == nil {
		return errors.New("producer not initialized")
	}

	if len(msg) == 0 {
		return errors.New("message should not be empty")
	}

	partition := rand.Int31() % kep.Config.MaxPartitions

	kafkaEvent := make(chan kafka.Event)

	err = kep.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &kep.Topic, Partition: partition},
		Value:          msg,
	}, kafkaEvent)

	ev := <-kafkaEvent

	// cast to message
	if m, ok := ev.(*kafka.Message); ok {
		if m.TopicPartition.Error != nil {
			return m.TopicPartition.Error
		}
	}

	return
}

func (kep *KafkaEventProducer) Flush(timeout int) int {
	return kep.Producer.Flush(timeout)
}

func (kep *KafkaEventProducer) Events() chan kafka.Event {
	return kep.Producer.Events()
}

func (kep *KafkaEventProducer) Close() {
	if kep.Producer != nil {
		kep.Producer.Close()
	}
}

func NewKafkaProducer(topic string, config *KafkaProducerConfig) (kp *KafkaEventProducer, err error) {
	if config == nil {
		config = GetDefaultKafkaProducerConfig()
	}

	if config.Server == "" {
		return nil, errors.New("invalid kafka server")
	}

	if config.Timeout <= 0 {
		return nil, errors.New("invalid timeout")
	}

	if topic == "" {
		return nil, errors.New("invalid topic")
	}

	p, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers":  config.Server,
		"message.timeout.ms": int(config.Timeout.Milliseconds()),
	})

	if err != nil {
		return nil, err
	}

	return &KafkaEventProducer{
		Config:   config,
		Producer: p,
		Topic:    topic,
	}, nil
}

func GetDefaultKafkaProducerConfig() *KafkaProducerConfig {
	return &KafkaProducerConfig{
		Server:        DEFAULT_KAFKA_SERVER,
		Timeout:       DEFAULT_KAFKA_WRITE_TIMEOUT,
		Acks:          DEFAULT_ACKS,
		MaxPartitions: DEFAULT_MAX_PARTITIONS,
	}
}
