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

func TestCanaryProcessEventHandler_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		cph := &consumer.CanaryProcessEventHandler{
			QueryHandler: &dqh,
		}

		canaryScan := &scan.CanaryScan{
			Meta: &scan.CanaryScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshal to bytes
		canaryScanBytes, _ := json.Marshal(canaryScan)

		// create message
		msg := &kafka.Message{
			Value: canaryScanBytes,
		}

		// process
		err := cph.Process(msg, &msh)

		assert.Nil(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process invalid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(nil, nil)

		cph := &consumer.CanaryProcessEventHandler{
			QueryHandler: &dqh,
		}

		// create message
		msg := &kafka.Message{
			Value: []byte("invalid"),
		}

		// process
		err := cph.Process(msg, &msh)

		assert.Error(t, err)
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("process query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, custom_errors.NewGenericError(errors.New("some error"), true))

		cph := &consumer.CanaryProcessEventHandler{
			QueryHandler: &dqh,
		}

		canaryScan := &scan.CanaryScan{
			Meta: &scan.CanaryScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshal to bytes
		canaryScanBytes, _ := json.Marshal(canaryScan)

		// create message
		msg := &kafka.Message{
			Value: canaryScanBytes,
		}

		// process
		err := cph.Process(msg, &msh)

		assert.Nil(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process storage error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("some error"))

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		cph := &consumer.CanaryProcessEventHandler{
			QueryHandler: &dqh,
		}

		canaryScan := &scan.CanaryScan{
			Meta: &scan.CanaryScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshal to bytes
		canaryScanBytes, _ := json.Marshal(canaryScan)

		// create message
		msg := &kafka.Message{
			Value: canaryScanBytes,
		}

		// process
		err := cph.Process(msg, &msh)

		assert.Error(t, err, "should return an error on storage error")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
