package producer

import (
	"errors"
	"math/rand"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

const DEFAULT_KAFKA_WRITE_TIMEOUT = 1000 * time.Millisecond

type EventProducer interface {
	Produce(msg []byte) (err error)
}

type KafkaEventProducer struct {
	EventProducer

	Server  string
	Timeout time.Duration

	Producer *kafka.Producer
}

func (kep *KafkaEventProducer) Produce(msg []byte, topic string, partitions int) (err error) {
	if kep.Producer == nil {
		return errors.New("producer not initialized")
	}

	randomPartition := rand.Int() % partitions

	err = kep.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: int32(randomPartition)},
		Value:          msg,
	}, nil)

	if err != nil {
		return err
	}

	return nil
}
