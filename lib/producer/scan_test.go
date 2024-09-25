package producer_test

import (
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedScan struct {
	mock.Mock
}

func (ms *mockedScan) GetType() string {
	args := ms.Called()
	return args.String(0)
}

func (ms *mockedScan) GetMetaInformation() *scan.ScanMetaInformation {
	args := ms.Called()
	return args.Get(0).(*scan.ScanMetaInformation)
}

func (ms *mockedScan) Marshal() ([]byte, error) {
	args := ms.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (ms *mockedScan) GetIdentifier() string {
	args := ms.Called()
	return args.String(0)
}

type mockedKafkaEventProducer struct {
	mock.Mock
}

func (mkp *mockedKafkaEventProducer) Produce(b []byte, topic string) error {
	args := mkp.Called(b, topic)
	return args.Error(0)
}

func (mkp *mockedKafkaEventProducer) Close() {
	mkp.Called()
}

func (mkp *mockedKafkaEventProducer) Flush(timeout int) int {
	args := mkp.Called(timeout)
	return args.Int(0)
}

func (mkp *mockedKafkaEventProducer) Events() chan kafka.Event {
	args := mkp.Called()
	return args.Get(0).(chan kafka.Event)
}

func (mkp *mockedKafkaEventProducer) WatchEvents() {
	mkp.Called()
}

func TestScanProducer_Produce(t *testing.T) {
	t.Parallel()

	t.Run("valid producer", func(t *testing.T) {
		t.Parallel()

		p := &mockedKafkaEventProducer{}
		p.On("Produce", mock.Anything, mock.Anything).Return(nil)
		p.On("WatchEvents").Return()
		p.On("Close").Return(nil)

		sp := &producer.KafkaScanProducer{
			Producer: p,
		}

		scan := &scan.DDRScan{}
		err := sp.Produce(scan, "test-topic")

		assert.NoError(t, err)
	})

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.KafkaScanProducer{}

		scan := &scan.DDRScan{}
		err := sp.Produce(scan, "test-topic")

		assert.Error(t, err, "error should not be nil")
	})

	t.Run("error on marhsall", func(t *testing.T) {
		t.Parallel()

		ms := &mockedScan{}
		ms.On("Marshal").Return([]byte{}, assert.AnError)

		mp := &mockedKafkaEventProducer{}
		mp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mp.On("WatchEvents").Return()

		sp := &producer.KafkaScanProducer{
			Producer: mp,
		}

		err := sp.Produce(ms, "test-topic")

		assert.NotNil(t, err, "error should not be nil")
	})
}

func TestScanProducer_Close(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("WatchEvents").Return()
		mp.On("Close").Return()

		sp := &producer.KafkaScanProducer{
			Producer: mp,
		}

		sp.Close()

		mp.AssertCalled(t, "Close")
	})

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.KafkaScanProducer{}

		sp.Close()
	})
}

func TestScanProducer_Flush(t *testing.T) {
	t.Parallel()

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.KafkaScanProducer{}

		res := sp.Flush(0)

		assert.Equal(t, 0, res, "expected 0")
	})

	t.Run("valid flush", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("WatchEvents").Return()
		mp.On("Flush", mock.Anything).Return(1)

		sp := &producer.KafkaScanProducer{
			Producer: mp,
		}

		res := sp.Flush(0)

		assert.Equal(t, 1, res, "expected 1")
	})
}

func TestNewScanProducer(t *testing.T) {
	t.Parallel()

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp, err := producer.NewScanProducer(nil)

		assert.NoError(t, err, "error should be nil")
		assert.NotNil(t, sp, "producer should not be nil")
	})
}

func TestNewKafkaScanProducer(t *testing.T) {
	t.Parallel()

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()

		sp, err := producer.NewKafkaScanProducer(nil)

		assert.Error(t, err, "error should not be nil")
		assert.Nil(t, sp, "producer should be nil")
	})
}
