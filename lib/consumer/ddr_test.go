package consumer_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
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

func TestDDRScanConsumeHandler_Process(t *testing.T) {
	t.Parallel()

	t.Run("consume valid message", func(t *testing.T) {
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

	t.Run("consume invalid message", func(t *testing.T) {
		t.Parallel()

		res := &query.ConventionalDNSResponse{}

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(res, nil)

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		ph := &consumer.DDRProcessEventHandler{
			QueryHandler: &mqh,
		}

		msg := kafka.Message{
			Value: []byte("invalid message"),
		}

		err := ph.Process(&msg, &msh)

		assert.Error(t, err)
		msh.AssertNotCalled(t, "Store", mock.Anything)
	})

	t.Run("critical query error that is not no response", func(t *testing.T) {
		t.Parallel()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(custom_errors.ErrNoResponse, true))

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		ph := &consumer.DDRProcessEventHandler{
			QueryHandler: &mqh,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		scanBytes, _ := json.Marshal(scan)

		msg := kafka.Message{
			Value: scanBytes,
		}

		err := ph.Process(&msg, &msh)

		assert.NoError(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("critical query error", func(t *testing.T) {
		t.Parallel()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(custom_errors.ErrUnpackFailed, true))

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		ph := &consumer.DDRProcessEventHandler{
			QueryHandler: &mqh,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		scanBytes, _ := json.Marshal(scan)

		msg := kafka.Message{
			Value: scanBytes,
		}

		err := ph.Process(&msg, &msh)

		assert.NoError(t, err, "although there is a query error, the process handler does only care about handling errors")
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("storage error", func(t *testing.T) {
		t.Parallel()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("storage error"))

		ph := &consumer.DDRProcessEventHandler{
			QueryHandler: &mqh,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		scanBytes, _ := json.Marshal(scan)

		msg := kafka.Message{
			Value: scanBytes,
		}

		err := ph.Process(&msg, &msh)

		assert.Error(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})
}

type MockedProducerFactory struct {
	mock.Mock
}

func (mpf *MockedProducerFactory) Produce(ddrScan *scan.DDRScan, newScan scan.Scan, topic string) error {
	args := mpf.Called(ddrScan, newScan, topic)

	return args.Error(0)
}

func TestDoECertScanScheduler(t *testing.T) {
	t.Parallel()

	const vantagePoint = "test"

	t.Run("schedule scans", func(t *testing.T) {
		t.Parallel()

		mpf := &MockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		scheduler := consumer.DoECertScanScheduler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleDoEScans: true,
			},
			Query: &query.ConventionalDNSQuery{},
			Result: &query.ConventionalDNSResponse{
				Response: &query.DNSResponse{
					ResponseMsg: &dns.Msg{
						Answer: []dns.RR{
							&dns.SVCB{
								Priority: 1,
								Target:   "example.com",
								Value: []dns.SVCBKeyValue{
									&dns.SVCBAlpn{
										Alpn: []string{"h2", "dot", "doq"},
									},
									&dns.SVCBDoHPath{
										Template: "/dns-query",
									},
								},
							},
						},
					},
				},
			},
		}

		scheduler.ScheduleScans(scan)

		mpf.AssertCalled(t, "Produce", mock.Anything, mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOH_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOQ_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOT_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_CERTIFICATE_TOPIC, vantagePoint))
	})

	t.Run("schedule scans no response", func(t *testing.T) {
		t.Parallel()

		mpf := &MockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		scheduler := consumer.DoECertScanScheduler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
				ScheduleDoEScans:    true,
			},
			Query:  &query.ConventionalDNSQuery{},
			Result: &query.ConventionalDNSResponse{},
		}

		scheduler.ScheduleScans(scan)

		mpf.AssertNotCalled(t, "Produce", mock.Anything, mock.Anything, mock.Anything)
	})
}

func TestPTRScanScheduler(t *testing.T) {
	t.Parallel()

	t.Run("schedule valid PTR scan", func(t *testing.T) {
		t.Parallel()

		mpf := &MockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		scheduler := consumer.PTRScanScheduler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "8.8.8.8",
					Port: 53,
				},
			},
		}

		scheduler.ScheduleScans(scan)

		assert.True(t, scan.Meta.PTRScheduled)
		mpf.AssertCalled(t, "Produce", mock.Anything, mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, scan.Meta.VantagePoint))
	})

	t.Run("schedule no PTR scan on hostname", func(t *testing.T) {
		t.Parallel()

		mpf := &MockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		scheduler := consumer.PTRScanScheduler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "google.de",
					Port: 53,
				},
			},
		}

		scheduler.ScheduleScans(scan)

		assert.False(t, scan.Meta.PTRScheduled)
		mpf.AssertNotCalled(t, "Produce", mock.Anything, mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, scan.Meta.VantagePoint))
	})
}
