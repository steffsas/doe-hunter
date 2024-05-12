package consumer_test

import (
	"encoding/json"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func TestDDRScanConsumeHandler_Consume(t *testing.T) {
	// t.Run("consume valid kafka message", func(t *testing.T) {
	// 	t.Parallel()

	// 	scan := generateValidScanKafkaMsg(&scan.DDRScan{
	// 		Meta: scan.DDRScanMetaInformation{
	// 			ScanMetaInformation: scan.ScanMetaInformation{
	// 				ScanID: "test",
	// 			},
	// 		},
	// 		Scan: query.ConventionalDNSQuery{
	// 			DNSQuery: query.DNSQuery{
	// 				Host: "test",
	// 				Port: 53,
	// 			},
	// 		},
	// 	})

	// 	// setup
	// 	mkc := &MockedKafkaConsumer{}
	// 	mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)
	// 	mkc.On("Close").Return(nil)
	// 	mkc.On("ReadMessage", mock.Anything).Return(&kafka.Message{}, nil)

	// 	kc := &consumer.KafkaEventConsumer{
	// 		Consumer:       mkc,
	// 		StorageHandler: &storage.EmptyStorageHandler{},
	// 		ProcessHandler: &consumer.EmptyProcessHandler{},
	// 	}

	// 	// test
	// 	err := wrapConsume(kc.Consume)

	// 	assert.Nil(t, err, "expected no error")
	// })

	// t.Run("nil consumer", func(t *testing.T) {
	// 	kc := &consumer.KafkaEventConsumer{
	// 		Consumer:       nil,
	// 		StorageHandler: &storage.EmptyStorageHandler{},
	// 		ProcessHandler: &consumer.EmptyProcessHandler{},
	// 	}

	// 	err := kc.Consume(context.Background(), "test")
	// 	assert.NotNil(t, err, "expected error on nil consumer")
	// })

	// t.Run("nil storage", func(t *testing.T) {
	// 	kc := &consumer.KafkaEventConsumer{
	// 		Consumer:       &MockedKafkaConsumer{},
	// 		StorageHandler: nil,
	// 		ProcessHandler: &consumer.EmptyProcessHandler{},
	// 	}

	// 	err := kc.Consume(context.Background(), "test")
	// 	assert.NotNil(t, err, "expected error on nil storage")
	// })

	// t.Run("failed open storage", func(t *testing.T) {
	// 	mkc := &MockedKafkaConsumer{}

	// 	msh := &MockedStorageHandler{}
	// 	msh.On("Open").Return(errors.New("failed to open storage"))
	// 	msh.On("Close").Return(nil)

	// 	kc := &consumer.KafkaEventConsumer{
	// 		Consumer:       mkc,
	// 		StorageHandler: msh,
	// 		ProcessHandler: &consumer.EmptyProcessHandler{},
	// 	}

	// 	err := kc.Consume(context.Background(), "test")
	// 	assert.NotNil(t, err, "expected error on open storage")
	// })

	// t.Run("continue on process error", func(t *testing.T) {
	// 	mkc := &MockedKafkaConsumer{}
	// 	mkc.On("SubscribeTopics", mock.Anything, mock.Anything).Return(nil)

	// })
}

func generateValidScanKafkaMsg(scan *scan.DDRScan) *kafka.Message {
	b, err := json.Marshal(scan)
	if err != nil {
		panic(err)
	}

	return &kafka.Message{
		TopicPartition: kafka.TopicPartition{},
		Value:          b,
	}
}
