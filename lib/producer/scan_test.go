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

func (ms *mockedScan) Marshall() ([]byte, error) {
	args := ms.Called()
	return args.Get(0).([]byte), args.Error(1)
}

type mockedKafkaEventProducer struct {
	mock.Mock
}

func (mkp *mockedKafkaEventProducer) Produce(b []byte) error {
	args := mkp.Called(b)
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

func TestScanProducer_Produce(t *testing.T) {
	t.Parallel()

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.ScanProducer{}

		scan := &scan.DDRScan{}
		err := sp.Produce(scan)

		assert.NotNil(t, err, "error should not be nil")
	})

	t.Run("error on marhsall", func(t *testing.T) {
		t.Parallel()

		ms := &mockedScan{}
		ms.On("Marshall").Return([]byte{}, assert.AnError)

		mp := &mockedKafkaEventProducer{}
		mp.On("Produce", mock.Anything).Return(nil)

		sp := &producer.ScanProducer{
			Producer: mp,
		}

		err := sp.Produce(ms)

		assert.NotNil(t, err, "error should not be nil")
	})

	t.Run("valid produce", func(t *testing.T) {
		t.Parallel()

		ms := &mockedScan{}
		ms.On("Marshall").Return([]byte("test"), nil)

		mp := &mockedKafkaEventProducer{}
		mp.On("Produce", mock.Anything).Return(nil)

		sp := &producer.ScanProducer{
			Producer: mp,
		}

		err := sp.Produce(ms)

		assert.Nil(t, err, "error should be nil")
	})
}

func TestScanProducer_Close(t *testing.T) {
	t.Parallel()

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.ScanProducer{}

		sp.Close()
	})

	t.Run("valid close", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("Close").Return()

		sp := &producer.ScanProducer{
			Producer: mp,
		}

		sp.Close()
	})
}

func TestScanProducer_Flush(t *testing.T) {
	t.Parallel()

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.ScanProducer{}

		res := sp.Flush(0)

		assert.Equal(t, 0, res, "expected 0")
	})

	t.Run("valid flush", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("Flush", mock.Anything).Return(1)

		sp := &producer.ScanProducer{
			Producer: mp,
		}

		res := sp.Flush(0)

		assert.Equal(t, 1, res, "expected 1")
	})
}

func TestScanProducer_Events(t *testing.T) {
	t.Parallel()

	t.Run("nil producer", func(t *testing.T) {
		t.Parallel()

		sp := &producer.ScanProducer{}

		res := sp.Events()

		assert.Nil(t, res, "expected nil")
	})

	t.Run("valid events", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("Events").Return(make(chan kafka.Event))

		sp := &producer.ScanProducer{
			Producer: mp,
		}

		res := sp.Events()

		assert.NotNil(t, res, "expected not nil")
	})
}

func TestNewScanProducer(t *testing.T) {
	t.Parallel()

	t.Run("invalid topic", func(t *testing.T) {
		t.Parallel()

		sp, err := producer.NewScanProducer("", &producer.KafkaProducerConfig{})

		assert.NotNil(t, err, "error should not be nil")
		assert.Nil(t, sp, "producer should be nil")
	})

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("Close").Return()

		sp, err := producer.NewScanProducer("test", &producer.KafkaProducerConfig{})

		assert.NotNil(t, err, "error should not be nil")
		assert.Nil(t, sp, "producer should be nil")
	})

	t.Run("valid producer", func(t *testing.T) {
		t.Parallel()

		mp := &mockedKafkaEventProducer{}
		mp.On("Close").Return()

		sp, err := producer.NewScanProducer("test", producer.GetDefaultKafkaProducerConfig())

		assert.Nil(t, err, "error should be nil")
		assert.NotNil(t, sp, "producer should not be nil")
	})
}
