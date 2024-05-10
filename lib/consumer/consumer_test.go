package consumer_test

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockedKafkaError struct {
	mock.Mock
	error
}

func (mke *MockedKafkaError) IsTimeout() bool {
	args := mke.Called()
	return args.Bool(0)
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
	return args.Get(0).(*kafka.Message), args.Error(1)
}

func TestKafkaEventConsumer_Consume(t *testing.T) {
	disableLog()

	t.Run("valid consume", func(t *testing.T) {
		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
		}

		err := wrapConsume(kc.Consume)
		assert.Nil(t, err, "expected no error")

		kc.Close()
	})

	t.Run("failed subscribe", func(t *testing.T) {
		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(io.EOF)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on subscribe")
	})

	t.Run("timeout readmessage", func(t *testing.T) {
		mke := &MockedKafkaError{}
		mke.On("IsTimeout").Return(false)

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "should stop consuming")
	})

	t.Run("continue on timeout", func(t *testing.T) {
		mke := &MockedKafkaError{}
		mke.On("IsTimeout").Return(true)

		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, mke)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
		}

		err := wrapConsume(kc.Consume)
		assert.Nil(t, err, "expected only timeout error which should be skipped")
	})

	t.Run("failed read", func(t *testing.T) {
		mkc := &MockedKafkaConsumer{}
		mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
		mkc.On("Close").Return(nil)
		mkc.On("ReadMessage", mock.Anything).Return(nil, io.EOF)

		kc := &consumer.KafkaEventConsumer{
			Consumer:       mkc,
			StorageHandler: &storage.EmptyStorageHandler{},
			ProcessHandler: &consumer.EmptyProcessHandler{},
		}

		err := wrapConsume(kc.Consume)
		assert.NotNil(t, err, "expected error on EOF read")
	})
}

func disableLog() {
	logrus.SetOutput(io.Discard)
}

func wrapConsume(consume func(context context.Context, topic string) error) error {
	ctx, cancel := context.WithCancel(context.Background())

	wg := sync.WaitGroup{}
	wg.Add(1)

	var err error

	go func() {
		err = consume(ctx, "test")
		defer wg.Done()
	}()

	time.Sleep(100 * time.Millisecond)

	cancel()
	wg.Wait()
	return err
}
