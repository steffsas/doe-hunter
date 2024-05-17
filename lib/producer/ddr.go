package producer

import (
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func ProduceDDRScan(host string, port int, scheduleDoEScans bool) error {
	// create DDR query
	q := query.NewDDRQuery()
	q.Host = host
	q.AutoFallbackTCP = true
	q.Protocol = query.DNS_UDP
	q.Port = port

	// create a new DDR scan
	scan := scan.NewDDRScan(q, scheduleDoEScans)
	// create a new producer
	p, err := NewScanProducer(kafka.DEFAULT_DDR_TOPIC, nil)
	if err != nil {
		logrus.Errorf("failed to create DDR scan producer: %v", err)
		return err
	}

	// produce the scan
	err = p.Produce(scan)
	if err != nil {
		logrus.Errorf("failed to produce DDR scan: %v", err)
		return err
	}

	return nil
}
