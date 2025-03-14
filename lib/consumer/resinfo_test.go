package consumer_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/miekg/dns"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestResInfoConsumer_Process(t *testing.T) {
	t.Parallel()

	targetName := "resolver.dns4all.eu."

	t.Run("process valid message", func(t *testing.T) {
		t.Parallel()
		qh := new(mockedConventionalDNSQueryHandler)
		// Does not matter since we don't reach that point
		mockResponse := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
						&dns.RFC3597{
							Hdr: dns.RR_Header{
								Name:   "resolver.dns4all.eu.",
								Rrtype: query.TypeRESINFO,
							},
							Rdata: "08716e616d656d696e0e74656d702d646e7373656376616c1a696e666f75726c3d68747470733a2f2f646e7334616c6c2e6575",
						},
					},
				},
			},
		}
		qh.On("Query", mock.Anything).Return(mockResponse, nil)

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(nil)

		c := &consumer.ResInfoProcessConsumer{
			QueryHandler: qh,
		}

		scan := &scan.ResInfoScan{
			Meta: &scan.ResInfoScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			TargetName: targetName,
			Host:       targetName,
		}

		resInfoScanBytes, _ := json.Marshal(scan)
		msg := &kafka.Message{
			Value: resInfoScanBytes,
		}

		err := c.Process(msg, msh)
		assert.Nil(t, err, "should not have returned an error")
	})

	t.Run("store error", func(t *testing.T) {
		t.Parallel()

		qh := new(mockedConventionalDNSQueryHandler)

		mockResponse := &query.ConventionalDNSResponse{
			Response: &query.DNSResponse{
				ResponseMsg: &dns.Msg{
					Answer: []dns.RR{
						&dns.RFC3597{
							Hdr: dns.RR_Header{
								Name:   "resolver.dns4all.eu.",
								Rrtype: query.TypeRESINFO,
							},
							Rdata: "08716e616d656d696e0e74656d702d646e7373656376616c1a696e666f75726c3d68747470733a2f2f646e7334616c6c2e6575",
						},
					},
				},
			},
		}
		qh.On("Query", mock.Anything).Return(mockResponse, nil)

		msh := &mockedStorageHandler{}
		msh.On("Store", mock.Anything).Return(errors.New("storage error"))

		c := &consumer.ResInfoProcessConsumer{
			QueryHandler: qh,
		}

		scan := &scan.ResInfoScan{
			Meta: &scan.ResInfoScanMetaInformation{
				ScanMetaInformation: scan.ScanMetaInformation{},
			},
			TargetName: targetName,
			Host:       targetName,
		}

		resInfoScanBytes, _ := json.Marshal(scan)
		msg := &kafka.Message{
			Value: resInfoScanBytes,
		}

		err := c.Process(msg, msh)
		assert.Error(t, err, "should have returned an error")
	})
}

func TestResInfoConsumer_ParseResponse(t *testing.T) {
	t.Parallel()

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.RFC3597{
			Hdr: dns.RR_Header{
				Name:   "resolver.dns4all.eu.",
				Rrtype: query.TypeRESINFO,
			},
			Rdata: "08716e616d656d696e0e74656d702d646e7373656376616c1a696e666f75726c3d68747470733a2f2f646e7334616c6c2e6575",
		},
	}

	res, err := consumer.ParseResInfoResponse(msg)

	assert.Nil(t, err, "should not have returned an error")
	require.NotNil(t, res, "should have returned a result")
	assert.Equal(t, "qnamemin", res.Keys[0], "should have returned the correct key")
}

func TestResInfoConsumer_RealWorld(t *testing.T) {
	t.Parallel()

	target := "resolver.dns4all.eu."
	host := "resolver.dns4all.eu"

	scan := &scan.ResInfoScan{
		Meta: &scan.ResInfoScanMetaInformation{
			ScanMetaInformation: scan.ScanMetaInformation{},
		},
		TargetName: target,
		Host:       host,
	}

	qh := query.NewResInfoQueryHandler(nil)

	c := &consumer.ResInfoProcessConsumer{
		QueryHandler: qh,
	}

	c.StartResInfo(scan)

	assert.Nil(t, scan.Meta.Errors, "should not have returned an error")
	assert.NotNil(t, scan.Result, "should have returned a result")
}
