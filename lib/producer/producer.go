package producer

import (
	"errors"
	"math/rand"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	k "github.com/steffsas/doe-hunter/lib/kafka"
)

const DEFAULT_KAFKA_SERVER = "localhost:29092"
const DEFAULT_ACKS = "1"
const DEFAULT_PARTITIONS = 100
const DEFAULT_KAFKA_WRITE_TIMEOUT = 1000 * time.Millisecond

type KafkaProducerConfig struct {
	Server  string
	Timeout time.Duration
	Acks    string

	MaxPartitions     int
	ReplicationFactor int
}

type KafkaProducer interface {
	Produce(msg *kafka.Message, deliveryChan chan kafka.Event) (err error)
	Close()
}

type KafkaEventProducer struct {
	k.EventProducer

	Config   *KafkaProducerConfig
	Topic    string
	Producer KafkaProducer
}

func (kep *KafkaEventProducer) Produce(msg []byte) (err error) {
	if kep.Producer == nil {
		return errors.New("producer not initialized")
	}

	if len(msg) == 0 {
		return errors.New("message should not be empty")
	}

	randomPartition := rand.Int() % kep.Config.MaxPartitions

	logrus.Infof("Producing message to topic %s", kep.Topic)

	err = kep.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &kep.Topic, Partition: int32(randomPartition)},
		Value:          msg,
	}, nil)

	logrus.Info("Message produced")

	return
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

	if config.MaxPartitions <= 0 {
		return nil, errors.New("invalid partition count")
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
		MaxPartitions: DEFAULT_PARTITIONS,
	}
}
