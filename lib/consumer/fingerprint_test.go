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

type mockedSSHQueryHandler struct {
	mock.Mock
}

func (mssh *mockedSSHQueryHandler) Query(q *query.SSHQuery) (response *query.SSHResponse, err custom_errors.DoEErrors) {
	args := mssh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.SSHResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.SSHResponse), args.Get(1).(custom_errors.DoEErrors)
}

type mockedDNSQueryHandler struct {
	mock.Mock
}

func (mdqh *mockedDNSQueryHandler) Query(q *query.ConventionalDNSQuery) (response *query.ConventionalDNSResponse, err custom_errors.DoEErrors) {
	args := mdqh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.ConventionalDNSResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.ConventionalDNSResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestFingerprintProcessEventHandler_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		sqh := mockedSSHQueryHandler{}
		sqh.On("Query", mock.Anything).Return(&query.SSHResponse{}, nil)

		dph := &consumer.FingerprintProcessEventHandler{
			DNSQueryHandler: &dqh,
			SSHQueryHandler: &sqh,
		}

		fingerprintScan := &scan.FingerprintScan{
			Meta: &scan.FingerprintScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			SSHQuery:           &query.SSHQuery{},
			VersionBindQuery:   &query.ConventionalDNSQuery{},
			VersionServerQuery: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		fingerprintScanBytes, _ := json.Marshal(fingerprintScan)
		msg := &kafka.Message{
			Value: fingerprintScanBytes,
		}

		err := dph.Process(msg, &msh)
		assert.NoError(t, err)

		require.Greater(t, len(msh.Calls), 0)
		msh.AssertCalled(t, "Store", mock.Anything)

		fps := msh.Calls[0].Arguments[0].(*scan.FingerprintScan)

		assert.NotNil(t, fps.SSHResult)
		assert.NotNil(t, fps.VersionBindResult)
		assert.NotNil(t, fps.VersionServerResult)
	})

	t.Run("invalid message", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(nil, nil)

		sqh := mockedSSHQueryHandler{}
		sqh.On("Query", mock.Anything).Return(nil, nil)

		dph := &consumer.FingerprintProcessEventHandler{
			DNSQueryHandler: &dqh,
			SSHQueryHandler: &sqh,
		}

		// marshall to bytes
		msg := &kafka.Message{
			Value: []byte("invalid"),
		}

		err := dph.Process(msg, &msh)

		assert.Error(t, err)
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("ssh query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		sqh := mockedSSHQueryHandler{}
		sqh.On("Query", mock.Anything).Return(&query.SSHResponse{}, custom_errors.NewQueryError(errors.New("error"), false))

		dph := &consumer.FingerprintProcessEventHandler{
			DNSQueryHandler: &dqh,
			SSHQueryHandler: &sqh,
		}

		fingerprintScan := &scan.FingerprintScan{
			Meta: &scan.FingerprintScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			SSHQuery:           &query.SSHQuery{},
			VersionBindQuery:   &query.ConventionalDNSQuery{},
			VersionServerQuery: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		fingerprintScanBytes, _ := json.Marshal(fingerprintScan)
		msg := &kafka.Message{
			Value: fingerprintScanBytes,
		}

		err := dph.Process(msg, &msh)
		assert.Nil(t, err, "although there is a query error, the process handler does only care about handling errors")

		require.Greater(t, len(msh.Calls), 0)
		msh.AssertCalled(t, "Store", mock.Anything)

		fps := msh.Calls[0].Arguments[0].(*scan.FingerprintScan)

		assert.NotNil(t, fps.SSHResult)
		assert.Greater(t, len(fps.Meta.Errors), 0)

		assert.NotNil(t, fps.VersionBindResult)
		assert.NotNil(t, fps.VersionServerResult)
	})

	t.Run("dns query error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, custom_errors.NewQueryError(errors.New("error"), false))

		sqh := mockedSSHQueryHandler{}
		sqh.On("Query", mock.Anything).Return(&query.SSHResponse{}, nil)

		dph := &consumer.FingerprintProcessEventHandler{
			DNSQueryHandler: &dqh,
			SSHQueryHandler: &sqh,
		}

		fingerprintScan := &scan.FingerprintScan{
			Meta: &scan.FingerprintScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			SSHQuery:           &query.SSHQuery{},
			VersionBindQuery:   &query.ConventionalDNSQuery{},
			VersionServerQuery: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		fingerprintScanBytes, _ := json.Marshal(fingerprintScan)
		msg := &kafka.Message{
			Value: fingerprintScanBytes,
		}

		err := dph.Process(msg, &msh)
		assert.Nil(t, err, "although there is a query error, the process handler does only care about handling errors")

		require.Greater(t, len(msh.Calls), 0)
		msh.AssertCalled(t, "Store", mock.Anything)

		fps := msh.Calls[0].Arguments[0].(*scan.FingerprintScan)

		assert.NotNil(t, fps.SSHResult)
		assert.NotNil(t, fps.VersionBindResult)
		assert.Greater(t, len(fps.Meta.Errors), 0)
	})

	t.Run("storage error", func(t *testing.T) {
		t.Parallel()

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("some error"))

		dqh := mockedDNSQueryHandler{}
		dqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		sqh := mockedSSHQueryHandler{}
		sqh.On("Query", mock.Anything).Return(&query.SSHResponse{}, nil)

		dph := &consumer.FingerprintProcessEventHandler{
			DNSQueryHandler: &dqh,
			SSHQueryHandler: &sqh,
		}

		fingerprintScan := &scan.FingerprintScan{
			Meta: &scan.FingerprintScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			SSHQuery:           &query.SSHQuery{},
			VersionBindQuery:   &query.ConventionalDNSQuery{},
			VersionServerQuery: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		fingerprintScanBytes, _ := json.Marshal(fingerprintScan)
		msg := &kafka.Message{
			Value: fingerprintScanBytes,
		}

		err := dph.Process(msg, &msh)
		assert.Error(t, err, "should return an error on storage error")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
