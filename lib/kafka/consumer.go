package kafka

import (
	"context"
	"errors"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_KAFKA_READ_TIMEOUT = 1000 * time.Millisecond
const DEFAULT_KAFKA_SERVER = "localhost:29092"
const DEFAULT_KAFKA_CONSUMER_GROUP = "default-consumer-group"

type KafkaConsumerConfig struct {
	Server        string
	ConsumerGroup string
	Topic         string
}

type KafkaErr interface {
	IsTimeout() bool
	Error() string
}

type EventProcessHandler interface {
	Process(msg *kafka.Message, storage storage.StorageHandler) (err error)
}

type EventConsumer interface {
	Consume(ctx context.Context) (err error)
	Close() (err error)
}

type KafkaConsumer interface {
	SubscribeTopics(topics []string, rebalanceCb kafka.RebalanceCb) (err error)
	ReadMessage(timeout time.Duration) (msg *kafka.Message, err error)
	Close() (err error)
}

type EmptyProcessHandler struct {
	EventProcessHandler
}

func (eph *EmptyProcessHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	logrus.Info("process handler not implemented")
	return nil
}

type KafkaEventConsumer struct {
	EventConsumer

	Timeout time.Duration

	Config         *KafkaConsumerConfig
	ProcessHandler EventProcessHandler
	StorageHandler storage.StorageHandler
	Consumer       KafkaConsumer
}

func (keh *KafkaEventConsumer) Consume(ctx context.Context) error {
	if keh.Consumer == nil {
		return errors.New("kafka consumer not initialized")
	}

	if keh.StorageHandler == nil {
		return errors.New("storage handler not initialized")
	}

	// open connection to storage
	err := keh.StorageHandler.Open()
	if err != nil {
		logrus.Errorf("failed to open storage handler: %v", err)
		return err
	}
	defer keh.StorageHandler.Close()

	// subscribe to Kafka topic
	err = keh.Consumer.SubscribeTopics([]string{keh.Config.Topic}, nil)
	if err != nil {
		logrus.Errorf("failed to subscribe to topic: %v", err)
		return err
	}
	defer keh.Consumer.Close()

	for {
		select {
		case <-ctx.Done():
			logrus.Info("received termination signal ")
			return nil
		default:
			msg, err := keh.Consumer.ReadMessage(keh.Timeout)
			if err != nil {
				// nolint: errorlint
				kfkerr, ok := err.(KafkaErr)
				if ok {
					// we ignore timeouts
					if !kfkerr.IsTimeout() {
						logrus.Error("kafka error reading message", err.Error())
						return err
					}
				} else {
					logrus.Error("unknown error while reading message", err.Error())
					return err
				}
			} else {
				// we got a message, let's process it
				err := keh.ProcessHandler.Process(msg, keh.StorageHandler)
				if err != nil {
					logrus.Errorf("failed to process message: %v", err)
					continue
				}
			}
		}
	}
}

func (keh *KafkaEventConsumer) Close() (err error) {
	if keh.Consumer == nil {
		return nil
	}

	err = keh.Consumer.Close()
	return
}

func NewKafkaEventConsumer(config *KafkaConsumerConfig, processHandler EventProcessHandler, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config == nil {
		config = GetDefaultKafkaConsumerConfig("na", "na")
	}

	if processHandler == nil {
		return nil, errors.New("process handler not set")
	}

	if storageHandler == nil {
		return nil, errors.New("storage handler not set")
	}

	if config.ConsumerGroup == "" {
		return nil, errors.New("consumer group not set")
	}

	if config.Server == "" {
		return nil, errors.New("server not set")
	}

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  config.Server,
		"group.id":           config.ConsumerGroup,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": "true",
	})

	kec = &KafkaEventConsumer{
		Config:         config,
		Consumer:       consumer,
		Timeout:        DEFAULT_KAFKA_READ_TIMEOUT,
		ProcessHandler: processHandler,
		StorageHandler: storageHandler,
	}

	return
}

func GetDefaultKafkaConsumerConfig(consumerGroup string, topic string) *KafkaConsumerConfig {
	return &KafkaConsumerConfig{
		Server:        DEFAULT_KAFKA_SERVER,
		ConsumerGroup: consumerGroup,
		Topic:         topic,
	}
}
