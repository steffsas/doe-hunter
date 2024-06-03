package consumer

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_CONCURRENT_THREADS = 100

type KafkaConsumerConfig struct {
	Server        string
	ConsumerGroup string
	Topic         string
	Threads       int
	Timeout       time.Duration
}

type KafkaErr interface {
	IsTimeout() bool
	Error() string
	Code() kafka.ErrorCode
}

type EventProcessHandler interface {
	Process(msg *kafka.Message, storage storage.StorageHandler) (err error)
}

type NewEventProcessHandlerFunc func() (EventProcessHandler, error)

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
	logrus.Debug("processing message, sleep 100 ms")
	time.Sleep(100 * time.Millisecond)
	return nil
}

type KafkaEventConsumer struct {
	Config            *KafkaConsumerConfig
	NewProcessHandler NewEventProcessHandlerFunc
	StorageHandler    storage.StorageHandler
	Consumer          KafkaConsumer
}

func (keh *KafkaEventConsumer) Consume(ctx context.Context) error {
	if keh.Consumer == nil {
		return errors.New("kafka consumer not initialized")
	}

	if keh.StorageHandler == nil {
		return errors.New("storage handler not initialized")
	}

	if keh.Config == nil {
		return errors.New("kafka consumer config not initialized")
	}

	if keh.Config.Threads == 0 {
		return errors.New("concurrent threads not set but required")
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

	msgChan := make(chan *kafka.Message, keh.Config.Threads)

	// context for shutdown
	ctx, cancel := context.WithCancel(ctx)

	// channel to receive termination signal
	// we want to gracefully shutdown the workers
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM) // Handle SIGTERM and Ctrl+C

	// create first all handler before consuming messages
	handler := []EventProcessHandler{}
	for i := 0; i < keh.Config.Threads; i++ {
		ph, err := keh.NewProcessHandler()
		if err != nil {
			cancel()
			return err
		}
		handler = append(handler, ph)
	}

	wg := sync.WaitGroup{}

	// graceful shutdown handling
	go func() {
		for {
			select {
			case <-termChan:
				logrus.Info("received SIGTERM termination signal")
				cancel()
				return
			case <-ctx.Done():
				logrus.Info("received parent context termination signal")
				return
			}
		}
	}()

	// let's fetch messages from kafka
	var fetchErr error
	wg.Add(1)
	go func() {
		fetchErr = keh.Fetch(ctx, msgChan, &wg)
	}()

	// let's process messages
	for i := 0; i < keh.Config.Threads; i++ {
		wg.Add(1)
		go keh.Process(i, handler[i], msgChan, &wg)
	}

	logrus.Infof("all %d worker started", keh.Config.Threads)

	wg.Wait()

	return fetchErr
}

func (keh *KafkaEventConsumer) Process(workerNum int, handler EventProcessHandler, in chan *kafka.Message, wg *sync.WaitGroup) {
	defer wg.Done()
	for msg := range in {
		// we got a message, let's process it
		logrus.Debugf("received message on topic %s and group %s", keh.Config.Topic, keh.Config.ConsumerGroup)
		err := handler.Process(msg, keh.StorageHandler)
		if err != nil {
			logrus.Errorf("worker %d failed to process message: %v", workerNum, err)
		}
	}
}

func (keh *KafkaEventConsumer) Fetch(ctx context.Context, out chan *kafka.Message, wg *sync.WaitGroup) (err error) {
	defer wg.Done()
	counter := 0
	for {
		select {
		case <-ctx.Done():
			logrus.Info("received termination signal, stop fetching messages")
			close(out)
			return
		default:
			msg, err := keh.Consumer.ReadMessage(keh.Config.Timeout)
			if err != nil {
				// nolint: errorlint
				kfkerr, ok := err.(KafkaErr)
				if ok {
					// we ignore timeouts
					if kfkerr.IsTimeout() {
						continue
					} else {
						logrus.Errorf("kafka error reading message: %s", err.Error())
						close(out)
						return err
					}
				} else {
					logrus.Errorf("unknown error while reading message: %s", err.Error())
					close(out)
					return err
				}
			} else {
				counter++
				if counter%1000 == 0 {
					logrus.Debugf("consumed %d messages from %s", counter, keh.Config.Topic)
				}
				out <- msg
			}
		}
	}
}

func (keh *KafkaEventConsumer) Close() (err error) {
	if keh.Consumer == nil {
		return nil
	}

	err = keh.Consumer.Close()
	if err != nil {
		return err
	}

	if keh.StorageHandler != nil {
		err = keh.StorageHandler.Close()
		if err != nil {
			return err
		}
	}

	return
}

func NewKafkaEventConsumer(config *KafkaConsumerConfig, newProcessHandler NewEventProcessHandlerFunc, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config == nil {
		return nil, errors.New("config not set")
	}

	if newProcessHandler == nil {
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

	if config.Threads <= 0 {
		return nil, errors.New("threads not set")
	}

	var consumer *kafka.Consumer
	consumer, err = kafka.NewConsumer(&kafka.ConfigMap{
		"bootstrap.servers":  config.Server,
		"group.id":           config.ConsumerGroup,
		"auto.offset.reset":  "earliest",
		"enable.auto.commit": "true",
	})
	if err != nil {
		return nil, err
	}

	kec = &KafkaEventConsumer{
		Config:            config,
		Consumer:          consumer,
		NewProcessHandler: newProcessHandler,
		StorageHandler:    storageHandler,
	}

	// create topic, make this beautfiul

	admin, err := kafka.NewAdminClientFromConsumer(consumer)
	if err != nil {
		return nil, err
	}
	defer admin.Close()

	_, err = admin.CreateTopics(context.Background(), []kafka.TopicSpecification{{
		Topic:         config.Topic,
		NumPartitions: k.DEFAULT_PARTITIONS,
	}})
	if err != nil {
		return nil, err
	}

	return kec, nil
}
