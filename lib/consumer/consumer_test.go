package consumer_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockedKafkaError struct {
	mock.Mock
}

func (mke *MockedKafkaError) IsTimeout() bool {
	args := mke.Called()
	return args.Bool(0)
}

func (mke *MockedKafkaError) Error() string {
	args := mke.Called()
	return args.String(0)
}

func (mke *MockedKafkaError) Code() kafka.ErrorCode {
	args := mke.Called()
	return args.Get(0).(kafka.ErrorCode)
}

type MockedKafkaConsumer struct {
	mock.Mock
}

func (mkc *MockedKafkaConsumer) Close() error {
	args := mkc.Called()
	return args.Error(0)
}

func (mkc *MockedKafkaConsumer) SubscribeTopics(topics []string, rebalanceCb kafka.RebalanceCb) error {
	args := mkc.Called(topics, rebalanceCb)
	return args.Error(0)
}

func (mkc *MockedKafkaConsumer) ReadMessage(timeout time.Duration) (*kafka.Message, error) {
	args := mkc.Called(timeout)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*kafka.Message), args.Error(1)
}

type MockedProcessHandler struct {
	mock.Mock
}

func (mph *MockedProcessHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	args := mph.Called(msg, storage)
	return args.Error(0)
}

type MockedStorageHandler struct {
	mock.Mock
}

func (msh *MockedStorageHandler) Store(msg interface{}) error {
	args := msh.Called(msg)
	return args.Error(0)
}

func (msh *MockedStorageHandler) Close() error {
	args := msh.Called()
	return args.Error(0)
}

func (msh *MockedStorageHandler) Open() error {
	args := msh.Called()
	return args.Error(0)
}

func TestKafkaEventConsumer_Consume(t *testing.T) {
	t.Parallel()

	t.Run("valid consume", func(t *testing.T) {
		t.Parallel()

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},

			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       2,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.Nil(t, err, "expected no error")

		kc.Close()
	})

	t.Run("nil consumer", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:       nil,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},

			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       10,
			},
		}

		err := kc.Consume(context.Background())
		assert.NotNil(t, err, "expected error on nil consumer")
	})

	t.Run("nil storage", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:       &MockedKafkaConsumer{},
			StorageHandler: nil,
			ProcessHandler: &consumer.EmptyProcessHandler{},

			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       10,
			},
		}

		err := kc.Consume(context.Background())
		assert.NotNil(t, err, "expected error on nil storage")
	})

	t.Run("failed open storage", func(t *testing.T) {
		t.Parallel()

		mkc := &MockedKafkaConsumer{}

		msh := &MockedStorageHandler{}
		msh.On("Open").Return(errors.New("failed to open storage"))
		msh.On("Close").Return(nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: msh,
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       10,
			},
		}

		err := kc.Consume(context.Background())
		assert.NotNil(t, err, "expected error on open storage")
	})

	t.Run("continue on process error", func(t *testing.T) {
		t.Parallel()

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

		mph := &MockedProcessHandler{}
		mph.On("Process", mock.Anything, mock.Anything).Return(errors.New("failed to process"))

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: mph,
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       100,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.Nil(t, err, "expect to continue on process error")
	})

	t.Run("ignore consumer nil on close", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:       nil,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       100,
			},
		}

		err := kc.Close()
		assert.Nil(t, err, "expected no error on nil consumer")
	})

	t.Run("failed subscribe", func(t *testing.T) {
		t.Parallel()

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(io.EOF)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       100,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on subscribe")
	})

	t.Run("timeout readmessage", func(t *testing.T) {
		t.Parallel()

		mke := &MockedKafkaError{}
		mke.On("IsTimeout").Return(false)
		mke.On("Error").Return("timeout")
		mke.On("Code").Return(kafka.ErrTimedOut)

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       1,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "should stop consuming")
	})

	t.Run("continue on timeout", func(t *testing.T) {
		t.Parallel()

		mke := &MockedKafkaError{}
		mke.On("IsTimeout").Return(true)
		mke.On("Error").Return("timeout")
		mke.On("Code").Return(kafka.ErrTimedOut)

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       100,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.Nil(t, err, "expected only timeout error which should be skipped")
		mke.AssertCalled(t, "IsTimeout")
	})

	t.Run("failed read", func(t *testing.T) {
		t.Parallel()

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(nil, io.EOF)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       100,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on EOF read")
	})

	t.Run("config required", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:       &MockedKafkaConsumer{},
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config:         nil,
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on missing config")
	})

	t.Run("must have at least one thread", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:       &MockedKafkaConsumer{},
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       0,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on zero threads")
	})
}

func TestKafkaEventConsumer_NewConsumer(t *testing.T) {
	t.Parallel()

	t.Run("no process handler", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(nil, nil, &storage.EmptyStorageHandler{})
		assert.NotNil(t, err, "expected error on nil process handler")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("no storage handler", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(nil, &consumer.EmptyProcessHandler{}, nil)
		assert.NotNil(t, err, "expected error on nil storage handler")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("nil consumer group config", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(&consumer.KafkaConsumerConfig{
			Server: "localhost:9092",
			Topic:  "test-topic",
		}, &consumer.EmptyProcessHandler{}, &storage.EmptyStorageHandler{})
		assert.NotNil(t, err, "expected error on nil consumer group config")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("nil server config", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(&consumer.KafkaConsumerConfig{
			Topic:         "test-topic",
			ConsumerGroup: "test",
		}, &consumer.EmptyProcessHandler{}, &storage.EmptyStorageHandler{})
		assert.NotNil(t, err, "expected error on nil consumer group config")
		assert.Nil(t, kc, "expected nil consumer on error")
	})
}

func wrapConsume(consume func(context context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)

	var err error

	go func() {
		defer wg.Done()
		err = consume(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	cancel()
	wg.Wait()
	return err
}
