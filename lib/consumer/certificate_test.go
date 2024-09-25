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

		// marshal to bytes
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

		assert.Error(t, err, "should return an error on invalid processing")
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

		// marshal to bytes
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

		// marshal to bytes
		certScanBytes, _ := json.Marshal(certScan)

		err := cc.Process(&kafka.Message{Value: certScanBytes}, msh)

		assert.Error(t, err, "storage errors should be returned")
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}

func TestCertificateEventConsumer_New(t *testing.T) {
	t.Parallel()

	t.Run("consumer group", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		mqh := &query.QueryConfig{}

		config := &consumer.KafkaConsumerConfig{}

		kec, err := consumer.NewKafkaCertificateEventConsumer(config, msh, mqh)

		assert.Error(t, err, "should return an error on missing kafka server information")
		assert.NotEmpty(t, config.ConsumerGroup, "should have added the default consumer group")
		assert.Nil(t, kec, "should return a valid KafkaEventConsumer")
	})

	t.Run("empty config", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}
		mqh := &query.QueryConfig{}

		kec, err := consumer.NewKafkaCertificateEventConsumer(nil, msh, mqh)

		assert.Error(t, err, "should return an error on empty config since kafka connection details are missing")
		assert.Nil(t, kec, "should return nil")
	})

	t.Run("empty storage handler", func(t *testing.T) {
		t.Parallel()

		mqh := &query.QueryConfig{}

		config := &consumer.KafkaConsumerConfig{
			ConsumerGroup: "test-group",
		}

		kec, err := consumer.NewKafkaCertificateEventConsumer(config, nil, mqh)

		assert.Error(t, err, "should return an error on empty storage handler")
		assert.Nil(t, kec, "should not return a valid KafkaEventConsumer")
	})

	t.Run("empty process handler", func(t *testing.T) {
		t.Parallel()

		msh := &mockedStorageHandler{}

		config := &consumer.KafkaConsumerConfig{
			ConsumerGroup: "test-group",
		}

		kec, err := consumer.NewKafkaCertificateEventConsumer(config, msh, nil)

		assert.Error(t, err, "should return an error on empty process handler")
		assert.Nil(t, kec, "should not return a valid KafkaEventConsumer")
	})
}
