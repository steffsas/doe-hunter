package consumer_test

// import (
// 	"encoding/json"
// 	"errors"
// 	"testing"

// 	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
// 	"github.com/miekg/dns"
// 	"github.com/steffsas/doe-hunter/lib/consumer"
// 	"github.com/steffsas/doe-hunter/lib/query"
// 	"github.com/steffsas/doe-hunter/lib/scan"
// 	"github.com/steffsas/doe-hunter/lib/storage"
// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/mock"
// )

// type MockedQueryHandler struct {
// 	mock.Mock
// }

// func (mqh *MockedQueryHandler) Query(q *query.ConventionalDNSQuery) (*query.ConventionalDNSResponse, error) {
// 	args := mqh.Called(q)
// 	return args.Get(0).(*query.ConventionalDNSResponse), args.Error(1)
// }

// func TestDDRScanConsumeHandler_Consume(t *testing.T) {
// 	disableLog()
// 	t.Parallel()

// 	qr := &query.ConventionalDNSResponse{
// 		Response: &query.DNSResponse{
// 			ResponseMsg: &dns.Msg{
// 				Answer: []dns.RR{
// 					&dns.SVCB{},
// 				},
// 			},
// 		},
// 	}

// 	mqh := &MockedQueryHandler{}
// 	mqh.On("Query", mock.Anything).Return(qr, nil)

// 	ph := &consumer.DDRProcessEventHandler{
// 		QueryHandler: mqh,
// 	}

// 	t.Run("consume valid kafka message", func(t *testing.T) {
// 		t.Parallel()

// 		scan := scan.NewDDRScan("8.8.8.8", 53, true)
// 		kfkMsg := generateValidScanKafkaMsg(scan)

// 		// setup
// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(kfkMsg, nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.Nil(t, err, "expected no error")
// 	})

// 	t.Run("nil consumer", func(t *testing.T) {
// 		t.Parallel()

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       nil,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.NotNil(t, err, "expected error on nil consumer")
// 	})

// 	t.Run("nil storage", func(t *testing.T) {
// 		t.Parallel()

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       &MockedKafkaConsumer{},
// 			StorageHandler: nil,
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.NotNil(t, err, "expected error on nil storage")
// 	})

// 	t.Run("failed open storage", func(t *testing.T) {
// 		t.Parallel()

// 		mkc := &MockedKafkaConsumer{}

// 		msh := &MockedStorageHandler{}
// 		msh.On("Open").Return(errors.New("failed to open storage"))
// 		msh.On("Close").Return(nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: msh,
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.NotNil(t, err, "expected error on open storage")
// 	})

// 	t.Run("failed store", func(t *testing.T) {
// 		t.Parallel()

// 		scan := scan.NewDDRScan("8.8.8.8", 53, true)
// 		kfkMsg := generateValidScanKafkaMsg(scan)

// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(kfkMsg, nil)

// 		msh := &MockedStorageHandler{}
// 		msh.On("Open").Return(nil)
// 		msh.On("Store", mock.Anything).Return(errors.New("failed to store"))
// 		msh.On("Close").Return(nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: msh,
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.Nil(t, err, "expected error on open storage, but should continue")
// 	})

// 	t.Run("empty kafka msg", func(t *testing.T) {
// 		t.Parallel()

// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(nil, nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.Nil(t, err, "expected no error, consume should continue")
// 	})

// 	t.Run("failed unmarshal", func(t *testing.T) {
// 		t.Parallel()

// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)

// 		assert.Nil(t, err, "expected no error, consume should continue")
// 	})

// 	t.Run("failed query", func(t *testing.T) {
// 		t.Parallel()

// 		qr := &query.ConventionalDNSResponse{
// 			Response: &query.DNSResponse{},
// 		}

// 		mqh := &MockedQueryHandler{}
// 		mqh.On("Query", mock.Anything).Return(qr, errors.New("failed to query"))

// 		ph := &consumer.DDRProcessEventHandler{
// 			QueryHandler: mqh,
// 		}

// 		scan := scan.NewDDRScan("8.8.8.8", 53, true)
// 		kfkMsg := generateValidScanKafkaMsg(scan)

// 		mkc := &MockedKafkaConsumer{}
// 		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
// 		mkc.On("Close").Return(nil)
// 		mkc.On("ReadMessage", mock.Anything).Return(kfkMsg, nil)

// 		kc := &consumer.KafkaEventConsumer{
// 			Consumer:       mkc,
// 			StorageHandler: &storage.EmptyStorageHandler{},
// 			ProcessHandler: ph,
// 		}

// 		// test
// 		err := wrapConsume(kc.Consume)
// 		assert.Nil(t, err, "expected no error, consume should continue")
// 	})
// }

// func TestNewKafkaEventConsumer(t *testing.T) {
// 	t.Parallel()

// 	t.Run("valid config", func(t *testing.T) {
// 		t.Parallel()
// 		config := &consumer.KafkaConsumerConfig{
// 			Server:        "localhost:9092",
// 			ConsumerGroup: "test",
// 		}

// 		msh := &storage.EmptyStorageHandler{}

// 		kc, err := consumer.NewKafkaDDREventConsumer(config, msh)

// 		assert.Nil(t, err, "expected no error on valid config")
// 		assert.NotNil(t, kc, "expected new kafka event consumer")
// 	})

// 	t.Run("nil config", func(t *testing.T) {
// 		t.Parallel()

// 		msh := &storage.EmptyStorageHandler{}

// 		kc, err := consumer.NewKafkaDDREventConsumer(nil, msh)

// 		assert.Nil(t, err, "expected no error on nil config, default config")
// 		assert.NotNil(t, kc, "expected no kafka event consumer")
// 	})

// 	t.Run("default consumer group", func(t *testing.T) {
// 		t.Parallel()

// 		config := &consumer.KafkaConsumerConfig{
// 			Server: "localhost:9092",
// 		}

// 		msh := &storage.EmptyStorageHandler{}

// 		kc, err := consumer.NewKafkaDDREventConsumer(config, msh)

// 		assert.Nil(t, err, "expected no error on default consumer group")
// 		assert.NotNil(t, kc, "expected new kafka event consumer")
// 		assert.Equal(t, kc.Config.ConsumerGroup, consumer.DEFAULT_DDR_CONSUMER_GROUP, "expected default consumer group")
// 	})
// }

// func TestNewKafkaDDRParallelEventConsumer(t *testing.T) {
// 	t.Parallel()
// 	disableLog()

// 	t.Run("valid config", func(t *testing.T) {
// 		t.Parallel()

// 		config := &consumer.KafkaParallelConsumerConfig{
// 			KafkaParallelEventConsumerConfig: &consumer.KafkaParallelEventConsumerConfig{
// 				ConcurrentConsumer: 1,
// 			},
// 			KafkaConsumerConfig: consumer.GetDefaultKafkaConsumerConfig(),
// 		}

// 		msh := &storage.EmptyStorageHandler{}

// 		kc, err := consumer.NewKafkaDDRParallelEventConsumer(config, msh)

// 		assert.Nil(t, err, "expected no error on valid config")
// 		assert.NotNil(t, kc, "expected new kafka parallel event consumer")
// 	})

// 	t.Run("nil config", func(t *testing.T) {
// 		t.Parallel()

// 		msh := &storage.EmptyStorageHandler{}

// 		kc, err := consumer.NewKafkaDDRParallelEventConsumer(nil, msh)

// 		assert.Nil(t, err, "expected no error on nil config")
// 		assert.NotNil(t, kc, "expected no kafka parallel event consumer")
// 		assert.Equal(t, kc.ConcurrentConsumer, consumer.DEFAULT_DDR_CONCURRENT_CONSUMER, "expected default concurrent consumer")
// 	})

// 	t.Run("nil storage", func(t *testing.T) {
// 		t.Parallel()

// 		config := &consumer.KafkaParallelConsumerConfig{
// 			KafkaParallelEventConsumerConfig: &consumer.KafkaParallelEventConsumerConfig{
// 				ConcurrentConsumer: 1,
// 			},
// 			KafkaConsumerConfig: consumer.GetDefaultKafkaConsumerConfig(),
// 		}

// 		kc, err := consumer.NewKafkaDDRParallelEventConsumer(config, nil)

// 		assert.NotNil(t, err, "expected error on nil storage")
// 		assert.Nil(t, kc, "expected no kafka parallel event consumer")
// 	})
// }

// func generateValidScanKafkaMsg(scan *scan.DDRScan) *kafka.Message {
// 	b, err := json.Marshal(scan)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return &kafka.Message{
// 		TopicPartition: kafka.TopicPartition{},
// 		Value:          b,
// 	}
// }
