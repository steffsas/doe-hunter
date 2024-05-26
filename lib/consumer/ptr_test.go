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

type mockedPTRQueryHandler struct {
	mock.Mock
}

func (mch *mockedPTRQueryHandler) Query(q *query.ConventionalDNSQuery) (response *query.ConventionalDNSResponse, err custom_errors.DoEErrors) {
	args := mch.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.ConventionalDNSResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.ConventionalDNSResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestPTR_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		pqh := mockedPTRQueryHandler{}
		pqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		pph := &consumer.PTRProcessEventHandler{
			QueryHandler: &pqh,
		}

		ptrScan := &scan.PTRScan{
			Meta: &scan.PTRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		ptrScanBytes, _ := json.Marshal(ptrScan)

		// test
		err := pph.Process(&kafka.Message{Value: ptrScanBytes}, &msh)

		assert.Nil(t, err, "should not return an error on valid processing msg")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process invalid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		pqh := mockedPTRQueryHandler{}
		pqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		pph := &consumer.PTRProcessEventHandler{
			QueryHandler: &pqh,
		}

		// test
		err := pph.Process(&kafka.Message{Value: []byte("invalid")}, &msh)

		assert.Error(t, err, "should return an error on invalid processing msg")
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("process query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		pqh := mockedPTRQueryHandler{}
		pqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(errors.New("some error"), true))

		pph := &consumer.PTRProcessEventHandler{
			QueryHandler: &pqh,
		}

		ptrScan := &scan.PTRScan{
			Meta: &scan.PTRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		ptrScanBytes, _ := json.Marshal(ptrScan)

		// test
		err := pph.Process(&kafka.Message{Value: ptrScanBytes}, &msh)

		assert.Nil(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process storage error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("some error"))

		pqh := mockedPTRQueryHandler{}
		pqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		pph := &consumer.PTRProcessEventHandler{
			QueryHandler: &pqh,
		}

		ptrScan := &scan.PTRScan{
			Meta: &scan.PTRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		ptrScanBytes, _ := json.Marshal(ptrScan)

		// test
		err := pph.Process(&kafka.Message{Value: ptrScanBytes}, &msh)

		assert.Error(t, err, "should return an error on storage error")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
