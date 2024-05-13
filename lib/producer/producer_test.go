package producer_test

import (
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockedKafkaProducer struct {
	mock.Mock
}

func (mkp *MockedKafkaProducer) Produce(msg *kafka.Message, deliveryChan chan kafka.Event) error {
	args := mkp.Called(msg, deliveryChan)
	return args.Error(0)
}

func (mkp *MockedKafkaProducer) Close() {
	mkp.Called()
}

func TestKafkaEventProducer_Produce(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		mp := &MockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic", 1)

		assert.Nil(t, err, "expected no error")
	})

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		kep := &producer.KafkaEventProducer{
			Producer: nil,
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic", 1)

		assert.NotNil(t, err, "expected error on nil producer")
	})

	t.Run("invalid partition count", func(t *testing.T) {
		t.Parallel()

		mp := &MockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic", 0)

		assert.NotNil(t, err, "expected error on invalid partition count")
	})

	t.Run("invalid topic", func(t *testing.T) {
		t.Parallel()

		mp := &MockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		// test
		err := kep.Produce([]byte("test"), "", 1)

		assert.NotNil(t, err, "expected error on invalid topic")
	})

	t.Run("empty message", func(t *testing.T) {
		t.Parallel()

		mp := &MockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		// test
		err := kep.Produce([]byte(""), "test-topic", 1)

		assert.NotNil(t, err, "expected error on empty message")
	})
}

func TestKafkaEventProducer_Close(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		mp := &MockedKafkaProducer{}
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		// test
		kep.Close()

		mp.AssertExpectations(t)
	})

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		kep := &producer.KafkaEventProducer{
			Producer: nil,
		}

		// test
		kep.Close()
	})
}

func TestNewKafkaProducer(t *testing.T) {
	t.Parallel()

	t.Run("invalid server", func(t *testing.T) {
		t.Parallel()

		p, err := producer.NewKafkaProducer(&producer.KafkaProducerConfig{
			Server: "",
		})

		assert.NotNil(t, err, "expected error on invalid producer")
		assert.Nil(t, p, "expected no producer")
	})

	t.Run("invalid timeout", func(t *testing.T) {
		t.Parallel()

		p, err := producer.NewKafkaProducer(&producer.KafkaProducerConfig{
			Server:  "localhost:9092",
			Timeout: -1,
		})

		assert.NotNil(t, err, "expected error on invalid producer")
		assert.Nil(t, p, "expected no producer")
	})

	t.Run("default config", func(t *testing.T) {
		t.Parallel()

		p, err := producer.NewKafkaProducer(nil)

		assert.Nil(t, err, "expected no error on default config")
		assert.NotNil(t, p, "expected new producer")
	})
}
