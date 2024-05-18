package producer

import (
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func ProduceDDRScans(resolvers []struct {
	Host string
	Port int
}, scheduleDoEScans bool) error {
	// create a new producer
	// create a new producer
	p, err := NewScanProducer(kafka.DEFAULT_DDR_TOPIC, nil)

	if err != nil {
		logrus.Errorf("failed to create DDR producer: %v", err)
		return err
	}

	wg := sync.WaitGroup{}

	for _, res := range resolvers {
		// create DDR query
		q := query.NewDDRQuery()
		q.Host = res.Host
		q.AutoFallbackTCP = true
		q.Protocol = query.DNS_UDP
		q.Port = res.Port

		// create a new DDR scan
		scan := scan.NewDDRScan(q, scheduleDoEScans)

		wg.Add(1)

		go func() {
			defer wg.Done()
			// produce the scan
			if err := p.Produce(scan); err != nil {
				logrus.Errorf("failed to produce DDR scan: %v", err)
			} else {
				logrus.Infof("produced DDR scan %s to scan resolver %s:%d", scan.GetScanId(), res.Host, res.Port)
			}
		}()
	}

	wg.Wait()

	// Flush and close the producer and the events channel
	for p.Flush(10000) > 0 {
		logrus.Info("still waiting for events to be flushed")
	}

	p.Close()

	return nil
}
