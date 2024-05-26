package kafka_test

import (
	"context"
	"errors"
	"testing"

	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockedKafkaEventConsumer struct {
	mock.Mock
}

func (mkec *MockedKafkaEventConsumer) Consume(ctx context.Context) error {
	args := mkec.Called(ctx)
	return args.Error(0)
}

func (mkec *MockedKafkaEventConsumer) Close() error {
	args := mkec.Called()
	return args.Error(0)
}

func TestParallelConsumer_Consume(t *testing.T) {
	t.Parallel()
	t.Run("valid consumer", func(t *testing.T) {
		t.Parallel()

		mkec := &MockedKafkaEventConsumer{}
		mkec.On("Consume", mock.Anything).Return(nil)
		mkec.On("Close").Return(nil)

		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// setup
		mc := &kafka.KafkaParallelConsumer{
			Config: config,
			CreateConsumer: func() (kafka.EventConsumer, error) {
				return mkec, nil
			},
		}

		// test
		err := wrapConsume(mc.Consume)

		assert.Nil(t, err, "expected no error on valid configuration and consumer")
	})

	t.Run("nil consumer and nil error", func(t *testing.T) {
		t.Parallel()

		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// setup
		mc := &kafka.KafkaParallelConsumer{
			Config: config,
			CreateConsumer: func() (kafka.EventConsumer, error) {
				return nil, nil
			},
		}

		// test
		err := wrapConsume(mc.Consume)

		assert.NotNil(t, err, "expected error on nil consumer")
	})

	t.Run("error on consumer creation", func(t *testing.T) {
		t.Parallel()

		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// setup
		mc := &kafka.KafkaParallelConsumer{
			Config: config,
			CreateConsumer: func() (kafka.EventConsumer, error) {
				return nil, errors.New("error")
			},
		}

		// test
		err := wrapConsume(mc.Consume)

		assert.NotNil(t, err, "expected error on nil consumer")
	})

	t.Run("negative or zero concurrent consumer", func(t *testing.T) {
		t.Parallel()

		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 0,
		}

		// setup
		mc := &kafka.KafkaParallelConsumer{
			Config: config,
			CreateConsumer: func() (kafka.EventConsumer, error) {
				return nil, nil
			},
		}

		// test
		err := wrapConsume(mc.Consume)

		assert.NotNil(t, err, "expected error on invalid concurrent consumer number")
	})

	t.Run("no consumer creation method given", func(t *testing.T) {
		t.Parallel()

		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// setup
		mc := &kafka.KafkaParallelConsumer{
			Config: config,
		}

		// test
		err := wrapConsume(mc.Consume)

		assert.NotNil(t, err, "expected error on nil consumer creation method")
	})

	t.Run("error on consume", func(t *testing.T) {
		t.Parallel()

		mkec := &MockedKafkaEventConsumer{}
		mkec.On("Consume", mock.Anything, mock.Anything).Return(errors.New("error"))
		mkec.On("Close").Return(nil)

		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// setup
		mc := &kafka.KafkaParallelConsumer{
			Config: config,
			CreateConsumer: func() (kafka.EventConsumer, error) {
				return mkec, nil
			},
		}

		// test
		err := wrapConsume(mc.Consume)

		assert.NotNil(t, err, "expected error on consume")
	})
}

func TestKafkaParallelConsumer_New(t *testing.T) {
	t.Parallel()
	t.Run("valid config", func(t *testing.T) {
		t.Parallel()

		// setup
		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// test
		mc, err := kafka.NewKafkaParallelEventConsumer(func() (kafka.EventConsumer, error) {
			return nil, nil
		}, config)

		assert.Nil(t, err, "expected no error on valid configuration")
		assert.NotNil(t, mc, "expected consumer")
	})

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()

		// test
		mc, err := kafka.NewKafkaParallelEventConsumer(func() (kafka.EventConsumer, error) {
			return nil, nil
		}, nil)

		assert.NotNil(t, err, "expected error on nil configuration")
		assert.Nil(t, mc, "expected no consumer")
	})

	t.Run("invalid concurrent consumer number", func(t *testing.T) {
		t.Parallel()

		// setup
		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 0,
		}

		// test
		mc, err := kafka.NewKafkaParallelEventConsumer(func() (kafka.EventConsumer, error) {
			return nil, nil
		}, config)

		assert.NotNil(t, err, "expected error on invalid concurrent consumer number")
		assert.Nil(t, mc, "expected no consumer")
	})

	t.Run("nil create consumer function", func(t *testing.T) {
		t.Parallel()

		// setup
		config := &kafka.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 10,
		}

		// test
		mc, err := kafka.NewKafkaParallelEventConsumer(nil, config)

		assert.NotNil(t, err, "expected error on nil create consumer function")
		assert.Nil(t, mc, "expected no consumer")
	})
}
