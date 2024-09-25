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
	"github.com/stretchr/testify/require"
)

func TestDDRDNSSECProcessConsumer_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := mockedConventionalDNSQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		dph := &consumer.DDRDNSSECProcessConsumer{
			QueryHandler: &cqh,
		}

		dnssecScan := &scan.DDRDNSSECScan{
			Meta: &scan.DDRDNSSECScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshal to bytes
		dnssecScanBytes, _ := json.Marshal(dnssecScan)
		msg := &kafka.Message{
			Value: dnssecScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.NoError(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("nil query message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := mockedConventionalDNSQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		dph := &consumer.DDRDNSSECProcessConsumer{
			QueryHandler: &cqh,
		}

		// test
		err := dph.Process(nil, &msh)

		assert.Error(t, err)
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("invalid query message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := mockedConventionalDNSQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		dph := &consumer.DDRDNSSECProcessConsumer{
			QueryHandler: &cqh,
		}

		// marshal to bytes
		msg := &kafka.Message{
			Value: []byte("invalid"),
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Error(t, err)
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := mockedConventionalDNSQueryHandler{}
		qErr := custom_errors.NewQueryError(custom_errors.ErrDNSPackFailed, true)
		cqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, qErr)

		dph := &consumer.DDRDNSSECProcessConsumer{
			QueryHandler: &cqh,
		}

		dnssecScan := &scan.DDRDNSSECScan{
			Meta: &scan.DDRDNSSECScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshal to bytes
		dnssecScanBytes, _ := json.Marshal(dnssecScan)
		msg := &kafka.Message{
			Value: dnssecScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.NoError(t, err) // query error should not return an error
		msh.AssertCalled(t, "Store", mock.Anything)

		storedDNSSECSan := msh.Calls[0].Arguments.Get(0).(*scan.DDRDNSSECScan)
		require.NotEmpty(t, storedDNSSECSan.Meta.Errors)
		assert.Contains(t, storedDNSSECSan.Meta.Errors, qErr)
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("error"))

		cqh := mockedConventionalDNSQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		dph := &consumer.DDRDNSSECProcessConsumer{
			QueryHandler: &cqh,
		}

		dnssecScan := &scan.DDRDNSSECScan{
			Meta: &scan.DDRDNSSECScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshal to bytes
		dnssecScanBytes, _ := json.Marshal(dnssecScan)
		msg := &kafka.Message{
			Value: dnssecScanBytes,
		}

		// test
		err := dph.Process(msg, &msh)

		assert.Error(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
