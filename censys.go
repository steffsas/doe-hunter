package main

import (
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func produceDDRScansFromCensys(filePath string, scheduleDoEScans bool, kafkaServer string, vantagePoint string) error {
	// read json file with censys data
	file, err := os.Open(filePath)
	if err != nil {
		logrus.Errorf("failed to open file: %v", err)
		return err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		logrus.Errorf("failed to read file: %v", err)
		return err
	}

	contentSplit := strings.Split(string(content), "\n")
	contentSplit = contentSplit[:len(contentSplit)-1] // remove last empty line

	// marshall the json data
	censysData := []scan.CensysData{}
	for _, line := range contentSplit {
		c := &scan.CensysData{}
		if err := json.Unmarshal([]byte(line), c); err != nil {
			logrus.Errorf("failed to unmarshal json: %v, %s", err, line)
			return err
		}
		censysData = append(censysData, *c)
	}

	logrus.Infof("got %d resolvers from censys data", len(censysData))

	// create a new producer
	config := producer.GetDefaultKafkaProducerConfig()
	config.Server = kafkaServer

	p, err := producer.NewKafkaScanProducer(config)
	if err != nil {
		logrus.Errorf("failed to create DDR producer: %v", err)
		return err
	}
	defer p.Close()

	wg := sync.WaitGroup{}

	ipv4Considered := []string{}
	ipv6Considered := []string{}

	runId := uuid.New().String()

	for _, res := range censysData {
		if res.Ipv4 != "" {
			if !slices.Contains(ipv4Considered, res.Ipv4) {
				ipv4Considered = append(ipv4Considered, res.Ipv4)

				// create DDR query
				q := query.NewDDRQuery()
				q.Host = res.Ipv4
				q.AutoFallbackTCP = true
				q.Protocol = query.DNS_UDP
				q.Port = 53

				// create scan
				scan := scan.NewDDRScan(q, scheduleDoEScans, runId, vantagePoint)
				scan.Meta.CensysData = res

				wg.Add(1)
				go scheduleDDRScan(scan, p, &wg)
			} else {
				logrus.Infof("skipping ipv4 %s as it was already considered", res.Ipv4)
			}
		}

		if res.Ipv6 != "" {
			if !slices.Contains(ipv6Considered, res.Ipv6) {
				ipv6Considered = append(ipv6Considered, res.Ipv6)

				// create DDR query
				q := query.NewDDRQuery()
				q.Host = res.Ipv6
				q.AutoFallbackTCP = true
				q.Protocol = query.DNS_UDP
				q.Port = 53

				// create scan
				scan := scan.NewDDRScan(q, scheduleDoEScans, vantagePoint, runId)
				scan.Meta.CensysData = res

				wg.Add(1)
				go scheduleDDRScan(scan, p, &wg)
			} else {
				logrus.Infof("skipping ipv6 %s as it was already considered", res.Ipv6)
			}
		}
	}

	wg.Wait()

	// Flush and close the producer and the events channel
	for p.Flush(10000) > 0 {
		logrus.Info("still waiting for events to be flushed")
	}

	return nil
}
