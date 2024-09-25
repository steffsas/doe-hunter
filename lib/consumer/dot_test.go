package consumer_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedDoTQueryHandler struct {
	mock.Mock
}

func (mdqh *mockedDoTQueryHandler) Query(q *query.DoTQuery) (response *query.DoTResponse, err custom_errors.DoEErrors) {
	args := mdqh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.DoTResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.DoTResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestDoTProcessEventHandler_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoTQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoTResponse{}, nil)

		dph := &consumer.DoTProcessEventHandler{
			QueryHandler: &dqh,
		}

		dotScan := &scan.DoTScan{
			Meta: &scan.DoTScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoTQuery{},
		}

		// marshal to bytes
		dotScanBytes, _ := json.Marshal(dotScan)

		// test
		msg := &kafka.Message{
			Value: dotScanBytes,
		}
		err := dph.Process(msg, &msh)

		assert.Nil(t, err, "should not return an error on valid processing msg")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process invalid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoTQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoTResponse{}, nil)

		dph := &consumer.DoTProcessEventHandler{
			QueryHandler: &dqh,
		}

		// test
		err := dph.Process(&kafka.Message{Value: []byte("invalid")}, &msh)

		assert.Error(t, err, "should return an error on invalid processing msg")
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("process query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoTQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoTResponse{}, custom_errors.NewGenericError(errors.New("some error"), true))

		dph := &consumer.DoTProcessEventHandler{
			QueryHandler: &dqh,
		}

		dotScan := &scan.DoTScan{
			Meta: &scan.DoTScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoTQuery{},
		}

		// marshal to bytes
		dotScanBytes, _ := json.Marshal(dotScan)

		// test
		err := dph.Process(&kafka.Message{Value: dotScanBytes}, &msh)

		assert.Nil(t, err, "should not return an error on valid processing msg")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process storage error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("some storage error"))

		dqh := mockedDoTQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoTResponse{}, nil)

		dph := &consumer.DoTProcessEventHandler{
			QueryHandler: &dqh,
		}

		dotScan := &scan.DoTScan{
			Meta: &scan.DoTScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoTQuery{},
		}

		// marshal to bytes
		dotScanBytes, _ := json.Marshal(dotScan)

		// test
		err := dph.Process(&kafka.Message{Value: dotScanBytes}, &msh)

		assert.Error(t, err, "should return an error on storage error")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
