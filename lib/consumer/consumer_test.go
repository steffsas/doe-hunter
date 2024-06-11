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

type mockedKafkaError struct {
	mock.Mock
}

func (mke *mockedKafkaError) IsTimeout() bool {
	args := mke.Called()
	return args.Bool(0)
}

func (mke *mockedKafkaError) Error() string {
	args := mke.Called()
	return args.String(0)
}

func (mke *mockedKafkaError) Code() kafka.ErrorCode {
	args := mke.Called()
	return args.Get(0).(kafka.ErrorCode)
}

type mockedKafkaConsumer struct {
	mock.Mock
}

func (mkc *mockedKafkaConsumer) Close() error {
	args := mkc.Called()
	return args.Error(0)
}

func (mkc *mockedKafkaConsumer) SubscribeTopics(topics []string, rebalanceCb kafka.RebalanceCb) error {
	args := mkc.Called(topics, rebalanceCb)
	return args.Error(0)
}

func (mkc *mockedKafkaConsumer) ReadMessage(timeout time.Duration) (*kafka.Message, error) {
	args := mkc.Called(timeout)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*kafka.Message), args.Error(1)
}

type mockedProcessHandler struct {
	mock.Mock
}

func (mph *mockedProcessHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	args := mph.Called(msg, storage)
	return args.Error(0)
}

func NewEmptyProcessHandler() (consumer.EventProcessHandler, error) {
	return &consumer.EmptyProcessHandler{}, nil
}

func TestKafkaEventConsumer_Consume(t *testing.T) {
	t.Parallel()

	t.Run("valid consume", func(t *testing.T) {
		t.Parallel()

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,

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
	})

	t.Run("nil consumer", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:          nil,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,

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
			Consumer:          &mockedKafkaConsumer{},
			StorageHandler:    nil,
			NewProcessHandler: NewEmptyProcessHandler,

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

		mkc := &mockedKafkaConsumer{}

		msh := &mockedStorageHandler{}
		msh.On("Open").Return(errors.New("failed to open storage"))
		msh.On("Close").Return(nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    msh,
			NewProcessHandler: NewEmptyProcessHandler,
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

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

		mph := func() (consumer.EventProcessHandler, error) {
			mph := &mockedProcessHandler{}
			mph.On("Process", mock.Anything, mock.Anything).Return(errors.New("failed to process"))
			return mph, nil
		}

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: mph,
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

	t.Run("failed subscribe", func(t *testing.T) {
		t.Parallel()

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(io.EOF)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,
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

		mke := &mockedKafkaError{}
		mke.On("IsTimeout").Return(false)
		mke.On("Error").Return("timeout")
		mke.On("Code").Return(kafka.ErrTimedOut)

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,
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

		mke := &mockedKafkaError{}
		mke.On("IsTimeout").Return(true)
		mke.On("Error").Return("timeout")
		mke.On("Code").Return(kafka.ErrTimedOut)

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,
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

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(nil, io.EOF)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,
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
			Consumer:          &mockedKafkaConsumer{},
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,
			Config:            nil,
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on missing config")
	})

	t.Run("must have at least one thread", func(t *testing.T) {
		t.Parallel()

		kc := &consumer.KafkaEventConsumer{
			Consumer:          &mockedKafkaConsumer{},
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: NewEmptyProcessHandler,
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

	t.Run("cancel context and threads on process handler creation", func(t *testing.T) {
		t.Parallel()

		mkc := &mockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

		mph := func() (consumer.EventProcessHandler, error) {
			return nil, errors.New("failed to create process handler")
		}

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    &storage.EmptyStorageHandler{},
			NewProcessHandler: mph,
			Config: &consumer.KafkaConsumerConfig{
				Server:        "localhost:9092",
				ConsumerGroup: "test",
				Topic:         "test-topic",
				Timeout:       100 * time.Millisecond,
				Threads:       10,
			},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on process handler creation")
	})
}

func TestKafkaEventConsumer_NewConsumer(t *testing.T) {
	t.Parallel()

	t.Run("no process handler", func(t *testing.T) {
		t.Parallel()

		config := &consumer.KafkaConsumerConfig{}

		kc, err := consumer.NewKafkaEventConsumer(config, nil, &storage.EmptyStorageHandler{})
		assert.NotNil(t, err, "expected error on nil process handler")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("no storage handler", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(nil, NewEmptyProcessHandler, nil)
		assert.NotNil(t, err, "expected error on nil storage handler")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("consumer group required", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(&consumer.KafkaConsumerConfig{
			Server:  "localhost:9092",
			Topic:   "test-topic",
			Threads: 10,
			Timeout: 100 * time.Millisecond,
		}, NewEmptyProcessHandler, &storage.EmptyStorageHandler{})
		assert.NotNil(t, err, "expected error on nil consumer group config")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("server required", func(t *testing.T) {
		t.Parallel()
		kc, err := consumer.NewKafkaEventConsumer(&consumer.KafkaConsumerConfig{
			Topic:         "test-topic",
			ConsumerGroup: "test",
			Threads:       10,
			Timeout:       100 * time.Millisecond,
		}, NewEmptyProcessHandler, &storage.EmptyStorageHandler{})
		assert.NotNil(t, err, "expected error on nil consumer group config")
		assert.Nil(t, kc, "expected nil consumer on error")
	})

	t.Run("number of threads required", func(t *testing.T) {
		t.Parallel()

		kc, err := consumer.NewKafkaEventConsumer(&consumer.KafkaConsumerConfig{
			Topic:         "test-topic",
			ConsumerGroup: "test",
			Server:        "localhost:9092",
			Timeout:       100 * time.Millisecond,
		}, NewEmptyProcessHandler, &storage.EmptyStorageHandler{})

		assert.NotNil(t, err, "expected error on nil consumer group config")
		assert.Nil(t, kc, "expected nil consumer on error")
	})
}

func TestKafkaEventConsumer_Close(t *testing.T) {
	t.Parallel()

	t.Run("valid close", func(t *testing.T) {
		t.Parallel()

		mkc := &mockedKafkaConsumer{}
		mkc.On("Close").Return(nil)

		msh := &mockedStorageHandler{}
		msh.On("Close").Return(nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    msh,
			NewProcessHandler: NewEmptyProcessHandler,
			Config:            &consumer.KafkaConsumerConfig{},
		}

		err := kc.Close()
		mkc.AssertCalled(t, "Close")
		msh.AssertCalled(t, "Close")
		assert.Nil(t, err, "expected no error")
	})

	t.Run("close storage error", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Close").Return(errors.New("failed to close storage"))

		mkc := &mockedKafkaConsumer{}
		mkc.On("Close").Return(nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    msh,
			NewProcessHandler: NewEmptyProcessHandler,
			Config:            &consumer.KafkaConsumerConfig{},
		}

		err := kc.Close()
		msh.AssertCalled(t, "Close")
		mkc.AssertCalled(t, "Close")
		assert.NotNil(t, err, "expected error on close storage")
	})

	t.Run("close consumer error", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Close").Return(nil)

		mkc := &mockedKafkaConsumer{}
		mkc.On("Close").Return(errors.New("failed to close consumer"))

		kc := &consumer.KafkaEventConsumer{
			Consumer:          mkc,
			StorageHandler:    msh,
			NewProcessHandler: NewEmptyProcessHandler,
			Config:            &consumer.KafkaConsumerConfig{},
		}

		err := kc.Close()
		msh.AssertCalled(t, "Close")
		mkc.AssertCalled(t, "Close")
		assert.NotNil(t, err, "expected error on close storage")
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
