package consumer_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedDoQQueryHandler struct {
	mock.Mock
}

func (mdqh *mockedDoQQueryHandler) Query(q *query.DoQQuery) (response *query.DoQResponse, err custom_errors.DoEErrors) {
	args := mdqh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.DoQResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.DoQResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestDoQProcessEventHandler_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoQQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoQResponse{}, nil)

		dph := &consumer.DoQProcessEventHandler{
			QueryHandler: &dqh,
		}

		doqScan := &scan.DoQScan{
			Meta: &scan.DoQScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoQQuery{},
		}

		// marshall to bytes
		doqScanBytes, _ := json.Marshal(doqScan)

		// create kafka message
		msg := &kafka.Message{
			Value: doqScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Nil(t, err, "should not return an error on valid processing msg")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process invalid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoQQueryHandler{}
		dqh.On("Query", mock.Anything).Return(nil, nil)

		dph := &consumer.DoQProcessEventHandler{
			QueryHandler: &dqh,
		}

		msg := &kafka.Message{
			Value: []byte("invalid"),
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Error(t, err, "should return an error on invalid processing msg")
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("process query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoQQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoQResponse{}, custom_errors.NewGenericError(errors.New("some error"), true))

		dph := &consumer.DoQProcessEventHandler{
			QueryHandler: &dqh,
		}

		doqScan := &scan.DoQScan{
			Meta: &scan.DoQScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoQQuery{},
		}

		// marshall to bytes
		doqScanBytes, _ := json.Marshal(doqScan)

		// create kafka message
		msg := &kafka.Message{
			Value: doqScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Nil(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process storage error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("some error"))

		dqh := mockedDoQQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoQResponse{}, nil)

		dph := &consumer.DoQProcessEventHandler{
			QueryHandler: &dqh,
		}

		doqScan := &scan.DoQScan{
			Meta: &scan.DoQScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoQQuery{},
		}

		// marshall to bytes
		doqScanBytes, _ := json.Marshal(doqScan)

		// create kafka message
		msg := &kafka.Message{
			Value: doqScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Error(t, err, "should return an error on storage error")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}

func TestNewKafkaDoQParallelConsumer(t *testing.T) {
	t.Parallel()

	t.Run("valid consumer", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}

		config := k.GetDefaultKafkaParallelConsumerConfig("test", "test")

		kec, err := consumer.NewKafkaDoQParallelEventConsumer(config, &msh)

		assert.Nil(t, err, "should not return an error")
		assert.NotNil(t, kec, "should return a valid consumer")
	})

	t.Run("default config", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}

		kec, err := consumer.NewKafkaDoQParallelEventConsumer(nil, &msh)

		assert.Nil(t, err, "should not return an error")
		assert.NotNil(t, kec, "should return a valid consumer")
	})

	t.Run("no storage handler", func(t *testing.T) {
		t.Parallel()

		kec, err := consumer.NewKafkaDoQParallelEventConsumer(
			k.GetDefaultKafkaParallelConsumerConfig("test", "test"), nil)

		assert.Error(t, err, "should return an error on no storage handler")
		assert.Nil(t, kec, "should not return a valid consumer")
	})
}
