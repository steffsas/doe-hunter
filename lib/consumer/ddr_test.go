package consumer_test

import (
	"encoding/json"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockedDDRQueryHandler struct {
	mock.Mock
}

func (mqh *mockedDDRQueryHandler) Query(q *query.ConventionalDNSQuery) (*query.ConventionalDNSResponse, custom_errors.DoEErrors) {
	args := mqh.Called(q)

	if args.Get(1) == nil {
		return args.Get(0).(*query.ConventionalDNSResponse), nil
	}

	if args.Get(0) == nil {
		return nil, args.Get(1).(custom_errors.DoEErrors)
	}

	return args.Get(0).(*query.ConventionalDNSResponse), args.Get(1).(custom_errors.DoEErrors)
}

func TestDDRScanConsumeHandler_Consume(t *testing.T) {
	t.Parallel()

	t.Run("consume valid kafka message", func(t *testing.T) {
		t.Parallel()

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		ph := &consumer.DDRProcessEventHandler{
			QueryHandler: &mqh,
		}

		// marshall to bytes
		scanBytes, _ := json.Marshal(scan)

		msg := kafka.Message{
			Value: scanBytes,
		}

		err := ph.Process(&msg, &msh)

		assert.NoError(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}
