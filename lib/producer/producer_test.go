package producer_test

import (
	"errors"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedKafkaProducer struct {
	mock.Mock
}

//nolint:gochecknoglobals
var eventMsg kafka.Event = &kafka.Message{}

func (mkp *mockedKafkaProducer) Produce(msg *kafka.Message, deliveryChan chan kafka.Event) error {
	// return some event
	go func() {
		deliveryChan <- eventMsg
	}()

	args := mkp.Called(msg, deliveryChan)
	return args.Error(0)
}

func (mkp *mockedKafkaProducer) Close() {
	mkp.Called()
}

func (mkp *mockedKafkaProducer) Flush(timeout int) int {
	args := mkp.Called(timeout)
	return args.Int(0)
}

func (mkp *mockedKafkaProducer) Events() chan kafka.Event {
	args := mkp.Called()
	return args.Get(0).(chan kafka.Event)
}

func TestKafkaEventProducer_Produce(t *testing.T) {
	t.Run("valid produce", func(t *testing.T) {
		mp := &mockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
			Config: &producer.KafkaProducerConfig{
				Server:            "localhost:9092",
				MaxPartitions:     100,
				Timeout:           1000,
				Acks:              "1",
				ReplicationFactor: 1,
			},
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic")

		assert.NoError(t, err, "expected no error")
	})

	t.Run("nil producer", func(t *testing.T) {
		kep := &producer.KafkaEventProducer{
			Producer: nil,
			Config: &producer.KafkaProducerConfig{
				Server: "localhost:9092",
			},
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic")

		assert.NotNil(t, err, "expected error on nil producer")
	})

	t.Run("empty message", func(t *testing.T) {
		mp := &mockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
			Config: &producer.KafkaProducerConfig{
				Server: "localhost:9092",
			},
		}

		// test
		err := kep.Produce([]byte(""), "test-topic")

		assert.NotNil(t, err, "expected error on empty message")
	})

	t.Run("empty topic", func(t *testing.T) {
		mp := &mockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
			Config: &producer.KafkaProducerConfig{
				Server: "localhost:9092",
			},
		}

		// test
		err := kep.Produce([]byte("test"), "")

		assert.Error(t, err, "expected error on empty topic")
	})

	t.Run("error on produce", func(t *testing.T) {
		mp := &mockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(errors.New("got some error"))
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
			Config:   producer.GetDefaultKafkaProducerConfig(),
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic")

		assert.NotNil(t, err, "expected error on produce")
	})

	t.Run("partition error", func(t *testing.T) {
		mp := &mockedKafkaProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(errors.New("got some error"))
		mp.On("Close").Return()

		kep := &producer.KafkaEventProducer{
			Producer: mp,
			Config:   producer.GetDefaultKafkaProducerConfig(),
		}

		eventMsg = &kafka.Message{
			TopicPartition: kafka.TopicPartition{Error: errors.New("test")},
		}

		// test
		err := kep.Produce([]byte("test"), "test-topic")

		eventMsg = &kafka.Message{}

		assert.NotNil(t, err, "expected error on produce")
		assert.Equal(t, "test", err.Error(), "expected error message")
	})
}

func TestKafkaEventProducer_Close(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaProducer{}
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

func TestKafkaEventProducer_Flush(t *testing.T) {
	t.Parallel()

	t.Run("valid flush", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaProducer{}
		mp.On("Flush", mock.Anything).Return(0)

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		kep.Flush(1000)

		assert.Equal(t, "Flush", mp.Calls[0].Method)
	})
}

func TestKafkaEventProducer_Events(t *testing.T) {
	t.Run("valid flush", func(t *testing.T) {
		c := make(chan kafka.Event)

		mp := &mockedKafkaProducer{}
		mp.On("Events").Return(c)

		kep := &producer.KafkaEventProducer{
			Producer: mp,
		}

		kep.Events()

		assert.Equal(t, "Events", mp.Calls[0].Method)
	})
}

func TestNewKafkaProducer(t *testing.T) {
	t.Parallel()

	t.Run("invalid server", func(t *testing.T) {
		t.Parallel()

		config := &producer.KafkaProducerConfig{
			Server:  "",
			Timeout: 1000,
		}

		p, err := producer.NewKafkaProducer(config)

		assert.NotNil(t, err, "expected error on invalid server")
		assert.Nil(t, p, "expected no producer")
	})

	t.Run("invalid timeout", func(t *testing.T) {
		t.Parallel()

		config := &producer.KafkaProducerConfig{
			Server:  "test",
			Timeout: 0,
		}

		p, err := producer.NewKafkaProducer(config)

		assert.NotNil(t, err, "expected error on invalid timeout")
		assert.Nil(t, p, "expected no producer")
	})
}

func TestGetDefaultKafkaProducerConfig(t *testing.T) {
	t.Parallel()

	// test
	cfg := producer.GetDefaultKafkaProducerConfig()

	assert.NotNil(t, cfg, "expected default config")
	assert.Equal(t, producer.DEFAULT_KAFKA_SERVER, cfg.Server, "expected default server")
	assert.Equal(t, producer.DEFAULT_KAFKA_WRITE_TIMEOUT, cfg.Timeout, "expected default timeout")
	assert.Equal(t, producer.DEFAULT_ACKS, cfg.Acks, "expected default acks")
	assert.Equal(t, producer.DEFAULT_MAX_PARTITIONS, cfg.MaxPartitions, "expected default max partitions")
}