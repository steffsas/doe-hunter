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

type mockedDoHQueryHandler struct {
	mock.Mock
}

func (mdqh *mockedDoHQueryHandler) Query(q *query.DoHQuery) (response *query.DoHResponse, err custom_errors.DoEErrors) {
	args := mdqh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.DoHResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.DoHResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestDoHProcessEventHandler_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoHQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoHResponse{}, nil)

		dph := &consumer.DoHProcessEventHandler{
			QueryHandler: &dqh,
		}

		dohScan := &scan.DoHScan{
			Meta: &scan.DoHScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoHQuery{},
		}

		// marshal to bytes
		dohScanBytes, _ := json.Marshal(dohScan)
		msg := &kafka.Message{
			Value: dohScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.NoError(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process invalid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoHQueryHandler{}
		dqh.On("Query", mock.Anything).Return(nil, nil)

		dph := &consumer.DoHProcessEventHandler{
			QueryHandler: &dqh,
		}

		// marshal to bytes
		msg := &kafka.Message{
			Value: []byte("invalid message"),
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Error(t, err)
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("process query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDoHQueryHandler{}
		dqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(errors.New("some error"), true))

		dph := &consumer.DoHProcessEventHandler{
			QueryHandler: &dqh,
		}

		dohScan := &scan.DoHScan{
			Meta: &scan.DoHScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoHQuery{},
		}

		// marshal to bytes
		dohScanBytes, _ := json.Marshal(dohScan)
		msg := &kafka.Message{
			Value: dohScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.NoError(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process storage error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("some error"))

		dqh := mockedDoHQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.DoHResponse{}, nil)

		dph := &consumer.DoHProcessEventHandler{
			QueryHandler: &dqh,
		}

		dohScan := &scan.DoHScan{
			Meta: &scan.DoHScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.DoHQuery{},
		}

		// marshal to bytes
		dohScanBytes, _ := json.Marshal(dohScan)
		msg := &kafka.Message{
			Value: dohScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Error(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
