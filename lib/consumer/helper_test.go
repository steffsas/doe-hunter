package consumer_test

import (
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

func TestRedoDoEScanOnCertError(t *testing.T) {
	t.Parallel()

	t.Run("produce new scan on certificate error", func(t *testing.T) {
		t.Parallel()

		err := custom_errors.NewCertificateError(errors.New("certificate error"), true)
		oldScan := &scan.DoHScan{
			Meta: &scan.DoHScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: "vantage-point",
				},
			},
		}
		newScan := &scan.DoHScan{
			Meta:  &scan.DoHScanMetaInformation{},
			Query: &query.DoHQuery{},
		}

		p := &mockedProducerFactory{}
		p.On("Produce", mock.Anything, mock.Anything).Return(nil)
		p.On("Flush", mock.Anything).Return(0)
		p.On("Events").Return(make(chan kafka.Event))

		consumer.RedoDoEScanOnCertError(err, oldScan, newScan, p)

		assert.True(t, newScan.GetDoEQuery().SkipCertificateVerify)
		p.AssertCalled(t, "Produce", newScan, mock.Anything)
	})

	t.Run("add error to old scan", func(t *testing.T) {
		t.Parallel()

		err := custom_errors.NewCertificateError(errors.New("certificate error"), true)
		oldScan := &scan.DoHScan{
			Meta: &scan.DoHScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: "vantage-point",
				},
			},
		}
		newScan := &scan.DoHScan{
			Meta:  &scan.DoHScanMetaInformation{},
			Query: &query.DoHQuery{},
		}

		p := &mockedProducerFactory{}
		p.On("Produce", mock.Anything, mock.Anything).Return(errors.New("error"))
		p.On("Flush", mock.Anything).Return(0)
		p.On("Events").Return(make(chan kafka.Event))

		consumer.RedoDoEScanOnCertError(err, oldScan, newScan, p)

		p.AssertCalled(t, "Produce", newScan, mock.Anything)
		assert.NotEmpty(t, oldScan.GetMetaInformation().Errors)
	})

	t.Run("do not produce scan on non-certificate error", func(t *testing.T) {
		t.Parallel()

		err := custom_errors.NewUnknownError(errors.New("some error"), true)
		oldScan := &scan.DoHScan{
			Meta: &scan.DoHScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: "vantage-point",
				},
			},
		}
		newScan := &scan.DoHScan{
			Meta:  &scan.DoHScanMetaInformation{},
			Query: &query.DoHQuery{},
		}

		p := &mockedProducerFactory{}
		p.On("Produce", mock.Anything, mock.Anything).Return(errors.New("error"))
		p.On("Flush", mock.Anything).Return(0)
		p.On("Events").Return(make(chan kafka.Event))

		consumer.RedoDoEScanOnCertError(err, oldScan, newScan, p)

		p.AssertNotCalled(t, "Produce", newScan, mock.Anything)
		assert.Empty(t, oldScan.GetMetaInformation().Errors)
	})
}
