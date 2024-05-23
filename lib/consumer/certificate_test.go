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

type mockedStorageHandler struct {
	mock.Mock
}

func (msh *mockedStorageHandler) Store(scan interface{}) error {
	args := msh.Called(scan)
	return args.Error(0)
}

func (msh *mockedStorageHandler) Open() error {
	args := msh.Called()
	return args.Error(0)
}

func (msh *mockedStorageHandler) Close() error {
	args := msh.Called()
	return args.Error(0)
}

type mockedCertificateQueryHandler struct {
	mock.Mock
}

func (mch *mockedCertificateQueryHandler) Query(q *query.CertificateQuery) (response *query.CertificateResponse, err custom_errors.DoEErrors) {
	args := mch.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.CertificateResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.CertificateResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestCertificate_Process(t *testing.T) {
	t.Parallel()

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := &mockedCertificateQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.CertificateResponse{}, nil)

		cc := &consumer.CertificateProcessEventHandler{
			QueryHandler: cqh,
		}

		// test
		certScan := &scan.CertificateScan{
			Meta: &scan.CertificateScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					ScanId: "test",
				},
			},
			Query: &query.CertificateQuery{
				Host: "example.com",
				Port: 443,
			},
		}

		// marshall to bytes
		certScanBytes, _ := json.Marshal(certScan)

		err := cc.Process(&kafka.Message{Value: certScanBytes}, msh)

		assert.Nil(t, err, "should not return an error on valid processing")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process invalid message", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := &mockedCertificateQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.CertificateResponse{}, nil)

		cc := &consumer.CertificateProcessEventHandler{
			QueryHandler: cqh,
		}

		err := cc.Process(&kafka.Message{Value: []byte("some invalid bytes")}, msh)

		assert.NoError(t, err, "should not return an error on valid processing")
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("process query error", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		cqh := &mockedCertificateQueryHandler{}
		cqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(errors.New("some error"), true))

		cc := &consumer.CertificateProcessEventHandler{
			QueryHandler: cqh,
		}

		// test
		certScan := &scan.CertificateScan{
			Meta: &scan.CertificateScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					ScanId: "test",
				},
			},
			Query: &query.CertificateQuery{
				Host: "example.com",
				Port: 443,
			},
		}

		// marshall to bytes
		certScanBytes, _ := json.Marshal(certScan)

		err := cc.Process(&kafka.Message{Value: certScanBytes}, msh)

		assert.Nil(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("process storage error", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("storage error"))

		cqh := &mockedCertificateQueryHandler{}
		cqh.On("Query", mock.Anything).Return(&query.CertificateResponse{}, nil)

		cc := &consumer.CertificateProcessEventHandler{
			QueryHandler: cqh,
		}

		// test
		certScan := &scan.CertificateScan{
			Meta: &scan.CertificateScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					ScanId: "test",
				},
			},
			Query: &query.CertificateQuery{
				Host: "example.com",
				Port: 443,
			},
		}

		// marshall to bytes
		certScanBytes, _ := json.Marshal(certScan)

		err := cc.Process(&kafka.Message{Value: certScanBytes}, msh)

		assert.Error(t, err, "storage errors should be returned")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}

func TestNewKafkaCertificateParallelEventConsumer(t *testing.T) {
	t.Parallel()

	t.Run("valid consumer", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}

		config := k.GetDefaultKafkaParallelConsumerConfig("test", "test")

		kec, err := consumer.NewKafkaCertificateParallelEventConsumer(config, msh)

		assert.Nil(t, err, "should not return an error on valid consumer creation")
		assert.NotNil(t, kec, "should return a valid consumer")
	})

	t.Run("default config", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}

		kec, err := consumer.NewKafkaCertificateParallelEventConsumer(nil, msh)

		assert.Nil(t, err, "should not return an error on valid consumer creation")
		assert.NotNil(t, kec, "should return a valid consumer")
	})

	t.Run("no storage handler", func(t *testing.T) {
		t.Parallel()

		kec, err := consumer.NewKafkaCertificateParallelEventConsumer(nil, nil)

		assert.Error(t, err, "should return an error on invalid storage handler")
		assert.Nil(t, kec, "should not return a valid consumer")
	})
}
