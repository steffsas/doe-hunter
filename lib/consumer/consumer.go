package consumer

import (
	"context"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_KAFKA_READ_TIMEOUT = 1000 * time.Millisecond
const DEFAULT_KAFKA_SERVER = "localhost:9092"
const DEFAULT_KAFKA_CONSUMER_GROUP = "default-consumer-group"

type KafkaErr interface {
	IsTimeout() bool
	Error() string
}

type EventProcessHandler interface {
	Process(msg *kafka.Message) (res interface{}, err error)
}

type EventConsumer interface {
	Consume(ctx context.Context, topic string) (err error)
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

func (eph *EmptyProcessHandler) Process(msg *kafka.Message) (res interface{}, err error) {
	logrus.Info("process handler not implemented")
	return []byte{}, nil
}

type KafkaEventConsumer struct {
	EventConsumer

	Timeout time.Duration

	ProcessHandler EventProcessHandler
	StorageHandler storage.StorageHandler
	Consumer       KafkaConsumer
}

func (keh *KafkaEventConsumer) Consume(ctx context.Context, topic string) error {
	// subscribe to Kafka topic
	err := keh.Consumer.SubscribeTopics([]string{topic}, nil)
	if err != nil {
		logrus.Errorf("failed to subscribe to topic: %v", err)
		return err
	}
	defer keh.Consumer.Close()

	// open connection to storage
	err = keh.StorageHandler.Open()
	if err != nil {
		logrus.Errorf("failed to open storage handler: %v", err)
		return err
	}
	defer keh.StorageHandler.Close()

	for {
		select {
		case <-ctx.Done():
			logrus.Info("received termination signal ")
			return nil
		default:
			msg, err := keh.Consumer.ReadMessage(keh.Timeout)
			if err != nil {
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
				res, err := keh.ProcessHandler.Process(msg)
				if err != nil {
					logrus.Errorf("failed to process message: %v", err)
					continue
				}

				// store the result
				err = keh.StorageHandler.Store(res)
				if err != nil {
					logrus.Errorf("failed to store result: %v", err)
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

type KafkaConsumerConfig struct {
	Server        string
	ConsumerGroup string
}

func NewKafkaEventConsumer(config *KafkaConsumerConfig) (kec *KafkaEventConsumer, err error) {
	if config == nil {
		config = &KafkaConsumerConfig{
			Server:        DEFAULT_KAFKA_SERVER,
			ConsumerGroup: DEFAULT_KAFKA_CONSUMER_GROUP,
		}
	}

	if config.ConsumerGroup == "" {
		logrus.Infof("consumer group not set, using default %s", DEFAULT_KAFKA_CONSUMER_GROUP)
		config.ConsumerGroup = DEFAULT_KAFKA_CONSUMER_GROUP
	}

	if config.Server == "" {
		logrus.Infof("kafka server not set, using default %s", DEFAULT_KAFKA_SERVER)
		config.Server = DEFAULT_KAFKA_SERVER
	}

	consumer, err := kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  config.Server,
		"group.id":           config.ConsumerGroup,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": "true",
	})

	kec = &KafkaEventConsumer{
		Consumer:       consumer,
		Timeout:        DEFAULT_KAFKA_READ_TIMEOUT,
		ProcessHandler: &EmptyProcessHandler{},
	}

	return
}
