package producer

import (
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/helper"
)

const DEFAULT_KAFKA_SERVER = "localhost:29092"
const DEFAULT_ACKS = "1"
const DEFAULT_KAFKA_WRITE_TIMEOUT = 10000 * time.Millisecond
const DEFAULT_FLUSH_TIMEOUT_MS = 5000
const DEFAULT_MAX_PARTITIONS int32 = 100

// this collects messages until it flushes, it boosts performance
const DEFAULT_MSG_UNTIL_FLUSH = 10000

type EventProducer interface {
	Produce(msg []byte, topic string) (err error)
	Close()
	Flush(timeout int) int
}

type KafkaProducerConfig struct {
	Server  string
	Timeout time.Duration
	Acks    string

	ProducerChannelSize int
	MaxPartitions       int32
	ReplicationFactor   int
}

type KafkaProducer interface {
	Produce(msg *kafka.Message, deliveryChan chan kafka.Event) (err error)
	Flush(timeout int) int
	Events() chan kafka.Event
	Close()
}

type KafkaEventProducer struct {
	flushLock    sync.Mutex
	ProducedMsgs atomic.Int32
	closed       chan bool
	Config       *KafkaProducerConfig
	Producer     KafkaProducer
}

func (kep *KafkaEventProducer) WatchEvents() {
	if kep.Producer == nil {
		logrus.Warn("producer not initialized")
		return
	}

	go func() {
		for {
			select {
			case ev := <-kep.Producer.Events():
				if m, ok := ev.(*kafka.Message); ok {
					if m.TopicPartition.Error != nil {
						logrus.Errorf("error producing message: %v", m.TopicPartition.Error)
					}
				}
			case <-kep.closed:
				return
			}
		}
	}()
}

func (kep *KafkaEventProducer) Flush(timeout int) int {
	if kep.Producer == nil {
		logrus.Warn("producer not initialized")
		return 0
	}

	kep.flushLock.Lock()
	defer kep.flushLock.Unlock()

	if timeout <= 0 {
		pmsg := kep.ProducedMsgs.Load()

		if pmsg >= DEFAULT_MSG_UNTIL_FLUSH {
			timeout = DEFAULT_FLUSH_TIMEOUT_MS
			nonFlushedItems := kep.Producer.Flush(timeout)
			for nonFlushedItems > 0 {
				logrus.Warnf("could not flush all items to Kafka, non-flushed items: {%d}, retry...", nonFlushedItems)
				nonFlushedItems = kep.Producer.Flush(timeout)
			}

			kep.ProducedMsgs.Swap(0)
		}

		return 0
	}

	return kep.Producer.Flush(timeout)
}

// blocking call to produce a message
func (kep *KafkaEventProducer) Produce(msg []byte, topic string) (err error) {
	if kep.Producer == nil {
		return errors.New("producer not initialized")
	}

	if len(msg) == 0 {
		return errors.New("message should not be empty")
	}

	if topic == "" {
		return errors.New("topic should not be empty")
	}

	partition := rand.Int31() % kep.Config.MaxPartitions

	err = kep.Producer.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: partition},
		Value:          msg,
	}, nil)

	kep.ProducedMsgs.Add(1)
	kep.Flush(0)

	return
}

func (kep *KafkaEventProducer) Close() {
	if kep.Producer != nil {
		kep.Flush(DEFAULT_MSG_UNTIL_FLUSH)
		kep.closed <- true
		kep.Producer.Close()
	}
}

func NewKafkaProducer(config *KafkaProducerConfig, p KafkaProducer) (kp *KafkaEventProducer, err error) {
	if config == nil {
		config = GetDefaultKafkaProducerConfig()
	}

	if config.Server == "" {
		return nil, errors.New("invalid kafka server")
	}

	if config.Timeout <= 0 {
		return nil, errors.New("invalid timeout")
	}

	if p == nil {
		p, err = kafka.NewProducer(&kafka.ConfigMap{
			"bootstrap.servers":  config.Server,
			"message.timeout.ms": int(config.Timeout.Milliseconds()),
			"go.batch.producer":  true,
		})

		if err != nil {
			return nil, err
		}
	}

	kep := &KafkaEventProducer{
		flushLock:    sync.Mutex{},
		ProducedMsgs: atomic.Int32{},
		closed:       make(chan bool, 1),
		Config:       config,
		Producer:     p,
	}

	// start watching for kafka events in a separate goroutine
	kep.WatchEvents()

	return kep, nil
}

func GetDefaultKafkaProducerConfig() *KafkaProducerConfig {
	kafkaServer, _ := helper.GetEnvVar(helper.KAFKA_SERVER_ENV, false)
	if kafkaServer == "" {
		kafkaServer = DEFAULT_KAFKA_SERVER
	}

	return &KafkaProducerConfig{
		Server:        kafkaServer,
		Timeout:       DEFAULT_KAFKA_WRITE_TIMEOUT,
		Acks:          DEFAULT_ACKS,
		MaxPartitions: DEFAULT_MAX_PARTITIONS,
	}
}
