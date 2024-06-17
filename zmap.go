package main

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hpcloud/tail"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func produceFromZmap(folder string) {
	// watch the folder and spawn new producer for each file-
}

// timeAfterExit is a timer that exits this process if no new data is written to the file
func produceFromZmapFile(filepath string, timeAfterExit time.Duration) error {
	// tail the zmap output file (will contain IP addresses for scanning)
	tailChannel, err := tail.TailFile(filepath, tail.Config{
		Follow:    true,
		MustExist: true,
	})
	if err != nil {
		logrus.Fatalf("failed to tail (watch) zmap output file: %v", err)
		return err
	}

	// get vantage point
	vantagePoint := getEnvVar(VANTAGE_POINT_ENV)
	if vantagePoint == "" {
		logrus.Fatalf("vantage point not set")
		return errors.New("vantage point not set")
	}

	// create a new producer
	config := producer.GetDefaultKafkaProducerConfig()
	config.Server = getEnvVar(KAFKA_SERVER_ENV)

	p, err := producer.NewKafkaScanProducer(config)
	if err != nil {
		logrus.Errorf("failed to create DDR producer: %v", err)
		return err
	}
	defer p.Close()

	// create producer channel
	producerChannel := make(chan scan.Scan)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		// remember the time of the last read line
		lastReadLine := time.Now()

		for {
			select {
			case line := <-tailChannel.Lines:
				if line != nil {
					// update last read line
					lastReadLine = time.Now()

					// create new scan
					q := query.NewDDRQuery()
					q.Host = line.Text

					s := scan.NewDDRScan(q, true, uuid.New().String(), vantagePoint)

					// produce scan
					producerChannel <- s
				}
			default:
				// check if we should exit
				if time.Since(lastReadLine) > timeAfterExit {
					close(producerChannel)
					return
				}
			}
		}
	}()

	// produce scans
	go func() {
		defer wg.Done()

		// quits when producerChannel is closed and drained
		for s := range producerChannel {
			if err := p.Produce(s, consumer.GetKafkaVPTopic(kafka.DEFAULT_DDR_TOPIC, vantagePoint)); err != nil {
				logrus.Errorf("failed to produce DDR scan: %v", err)
			}
		}
	}()

	wg.Wait()
	return nil
}
