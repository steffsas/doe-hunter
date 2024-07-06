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
	"github.com/stretchr/testify/require"
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
	t.Run("consume valid message", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		mqh := &mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ddrph := &consumer.DDRProcessEventHandler{
			Producer:     mpf,
			QueryHandler: mqh,
		}

		// marshall to bytes
		scanBytes, _ := json.Marshal(scan)

		msg := kafka.Message{
			Value: scanBytes,
		}

		err := ddrph.Process(&msg, msh)

		assert.NoError(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
	})

	t.Run("consume invalid message", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		res := &query.ConventionalDNSResponse{}

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(res, nil)

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := &consumer.DDRProcessEventHandler{
			Producer:     mpf,
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
		defer consumer.ScanCache.Clear()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(custom_errors.ErrNoResponse, true))

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := &consumer.DDRProcessEventHandler{
			Producer:     mpf,
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
		defer consumer.ScanCache.Clear()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(nil, custom_errors.NewQueryError(custom_errors.ErrUnpackFailed, true))

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := &consumer.DDRProcessEventHandler{
			Producer:     mpf,
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
		defer consumer.ScanCache.Clear()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("storage error"))

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := &consumer.DDRProcessEventHandler{
			Producer:     mpf,
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

	t.Run("should not query ips on blocklist", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mqh := mockedDDRQueryHandler{}
		mqh.On("Query", mock.Anything).Return(&query.ConventionalDNSResponse{}, nil)

		msh := mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := &consumer.DDRProcessEventHandler{
			Producer:     mpf,
			QueryHandler: &mqh,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					IsOnBlocklist: true,
				},
			},
			Query: &query.ConventionalDNSQuery{},
		}

		// marshall to bytes
		scanBytes, _ := json.Marshal(scan)

		msg := kafka.Message{
			Value: scanBytes,
		}

		err := ph.Process(&msg, &msh)

		assert.NoError(t, err)
		msh.AssertCalled(t, "Store", mock.Anything)
		mqh.AssertNotCalled(t, "Query", mock.Anything)
	})
}

type mockedProducerFactory struct {
	mock.Mock
}

func (mpf *mockedProducerFactory) Produce(s scan.Scan, topic string) error {
	args := mpf.Called(s, topic)
	return args.Error(0)
}

func (mpf *mockedProducerFactory) Close() {
	mpf.Called()
}

func (mpf *mockedProducerFactory) Flush(timeout int) int {
	args := mpf.Called(timeout)
	return args.Int(0)
}

func TestDDRProcessEventHandler_ScheduleScans(t *testing.T) {
	const vantagePoint = "test"

	t.Run("schedule scans on response", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
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

		ph.ScheduleScans(scan)

		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOH_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOQ_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOT_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_CERTIFICATE_TOPIC, vantagePoint))
	})

	t.Run("cache scans", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		firstDDRScan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleFingerprintScan: true,
				ScheduleDoEScans:        true,
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

		secondDDRScan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleDoEScans:        true,
				ScheduleFingerprintScan: false, // needed for assertion later on
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

		ph.ScheduleScans(firstDDRScan)

		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOH_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOQ_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOT_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_CERTIFICATE_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_EDSR_TOPIC, vantagePoint))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_FINGERPRINT_TOPIC, vantagePoint))

		// check cache, i.e., the already produced scans are not produced again
		producerCounter := 0
		for _, c := range mpf.Calls {
			if c.Method == "Produce" {
				producerCounter++
			}
		}

		ph.ScheduleScans(secondDDRScan)

		// should not have called produce on DoE scans again
		mpf.AssertNumberOfCalls(t, "Produce", producerCounter)

		// check wether children are added properly
		assert.Greater(t, len(firstDDRScan.Meta.Children), 0)
		assert.Equal(t, len(firstDDRScan.Meta.Children), len(secondDDRScan.Meta.Children))
	})

	t.Run("do not schedule scans if there is no response", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
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

		ph.ScheduleScans(scan)

		mpf.AssertNotCalled(t, "Produce", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("add error to meta information", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		produceError := errors.New("some error")

		mpf := &mockedProducerFactory{}
		// failure on DoH produce
		mpf.On("Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_DOH_TOPIC, vantagePoint)).Return(produceError)
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
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
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		mpf.AssertCalled(t, "Produce", mock.Anything, mock.Anything)
		require.NotEmpty(t, scan.Meta.Errors)
		assert.Equal(t, 1, len(scan.Meta.Errors))
		assert.Contains(t, scan.Meta.Errors[0].Error(), produceError.Error())
	})

	t.Run("schedule PTR scan on query host IP address", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleDoEScans: true,
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "127.0.0.1",
				},
			},
			Result: &query.ConventionalDNSResponse{
				Response: &query.DNSResponse{
					ResponseMsg: &dns.Msg{
						Answer: []dns.RR{
							&dns.SVCB{
								Priority: 1,
								Target:   "example.com",
								Value: []dns.SVCBKeyValue{
									&dns.SVCBAlpn{
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, vantagePoint))
		require.Empty(t, scan.Meta.Errors)
		assert.True(t, scan.Meta.PTRScheduled)
	})

	t.Run("do not schedule PTR scan on query host domain name", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleDoEScans: true,
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "example.com",
				},
			},
			Result: &query.ConventionalDNSResponse{
				Response: &query.DNSResponse{
					ResponseMsg: &dns.Msg{
						Answer: []dns.RR{
							&dns.SVCB{
								Priority: 1,
								Target:   "example.com",
								Value: []dns.SVCBKeyValue{
									&dns.SVCBAlpn{
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		mpf.AssertNotCalled(t, "Produce", mock.Anything,
			consumer.GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, vantagePoint))
		require.Empty(t, scan.Meta.Errors)
		assert.False(t, scan.Meta.PTRScheduled)
	})

	t.Run("do not schedule DoE scans if not wanted", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleDoEScans: false,
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
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		mpf.AssertNotCalled(t, "Produce", mock.Anything, mock.Anything)
	})

	t.Run("add PTR produce error to meta data", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		produceError := errors.New("some error")

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, vantagePoint)).Return(produceError)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleDoEScans: true,
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "127.0.0.1",
				},
			},
		}

		ph.ScheduleScans(scan)

		require.NotEmpty(t, scan.Meta.Errors)
		assert.Equal(t, 1, len(scan.Meta.Errors))
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, vantagePoint))
	})

	t.Run("test fingerprint scan schedule", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleFingerprintScan: true,
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "example.com",
				},
			},
			Result: &query.ConventionalDNSResponse{
				Response: &query.DNSResponse{
					ResponseMsg: &dns.Msg{
						Answer: []dns.RR{
							&dns.SVCB{
								Priority: 1,
								Target:   "example.com",
								Value: []dns.SVCBKeyValue{
									&dns.SVCBAlpn{
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_FINGERPRINT_TOPIC, vantagePoint))
	})

	t.Run("test fingerprint scan no schedule", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleFingerprintScan: false,
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "example.com",
				},
			},
			Result: &query.ConventionalDNSResponse{
				Response: &query.DNSResponse{
					ResponseMsg: &dns.Msg{
						Answer: []dns.RR{
							&dns.SVCB{
								Priority: 1,
								Target:   "example.com",
								Value: []dns.SVCBKeyValue{
									&dns.SVCBAlpn{
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		mpf.AssertNotCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_FINGERPRINT_TOPIC, vantagePoint))
	})

	t.Run("test fingerprint scan error", func(t *testing.T) {
		defer consumer.ScanCache.Clear()

		mpf := &mockedProducerFactory{}
		mpf.On("Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_FINGERPRINT_TOPIC, vantagePoint)).Return(errors.New("some error"))
		mpf.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mpf.On("Flush", mock.Anything).Return(0)

		ph := consumer.DDRProcessEventHandler{
			Producer: mpf,
		}

		scan := &scan.DDRScan{
			Meta: &scan.DDRScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{
					VantagePoint: vantagePoint,
				},
				ScheduleFingerprintScan: true,
			},
			Query: &query.ConventionalDNSQuery{
				DNSQuery: query.DNSQuery{
					Host: "example.com",
				},
			},
			Result: &query.ConventionalDNSResponse{
				Response: &query.DNSResponse{
					ResponseMsg: &dns.Msg{
						Answer: []dns.RR{
							&dns.SVCB{
								Priority: 1,
								Target:   "example.com",
								Value: []dns.SVCBKeyValue{
									&dns.SVCBAlpn{
										Alpn: []string{"h2"},
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

		ph.ScheduleScans(scan)

		assert.NotEmpty(t, scan.Meta.Errors)
		mpf.AssertCalled(t, "Produce", mock.Anything, consumer.GetKafkaVPTopic(k.DEFAULT_FINGERPRINT_TOPIC, vantagePoint))
	})
}
