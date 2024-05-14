package producer

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
)

const DEFAULT_DDR_TOPIC = "ddr-scan"
const DEFAULT_DDR_PARTITIONS = 1

type DDRProducer struct {
	EventProducer

	Producer *KafkaEventProducer
	Config   *ProducerConfig
}

func (dp *DDRProducer) Produce() (err error) {
	if dp.Producer == nil {
		return errors.New("producer not initialized")
	}

	// read all resolvers
	file, err := os.Open("resolvers.txt")
	if err != nil {
		logrus.Errorf("failed to open resolvers file: %v", err)
		return
	}
	defer file.Close()

	// Use a Scanner to read line by line
	scanner := bufio.NewScanner(file)

	scans := []*scan.DDRScan{}

	// Loop through each line
	for scanner.Scan() {
		resolver := scanner.Text()
		scan := scan.NewDDRScan(resolver, 53, false)
		// udp is blocked
		scan.Query.Protocol = query.DNS_TCP
		scan.Meta.SetScheduled()
		scans = append(scans, scan)
	}

	// Check for any errors during scanning
	if err = scanner.Err(); err != nil {
		logrus.Errorf("failed to scan resolvers file: %v", err)
		return
	}

	for _, scan := range scans {
		logrus.Infof("create ddr scan for host %s on port %d", scan.Query.Host, scan.Query.Port)
		var scanMsg []byte
		scanMsg, err = json.Marshal(scan)
		if err != nil {
			logrus.Errorf("failed to marshal scan %s: %s", scan.Query.Host, err.Error())
			return
		}
		err = dp.Producer.Produce(scanMsg, dp.Config.Topic, dp.Config.MaxPartitions)
		if err != nil {
			logrus.Errorf("failed to produce scan %s: %s", scan.Query.Host, err.Error())
			return
		}
	}

	return
}

func (dp *DDRProducer) Close() {
	if dp.Producer != nil {
		dp.Producer.Close()
	}
}

func NewDefaultDDRProducerConfig() *ProducerConfig {
	return &ProducerConfig{
		KafkaProducerConfig: *GetDefaultKafkaProducerConfig(),
		Topic:               DEFAULT_DDR_TOPIC,
		MaxPartitions:       DEFAULT_DDR_PARTITIONS,
	}
}

func NewDDRProducer(config *ProducerConfig) (dp *DDRProducer, err error) {
	if config == nil {
		config = NewDefaultDDRProducerConfig()
	}

	if config.Server == "" {
		config.Server = DEFAULT_KAFKA_SERVER
	}

	if config.MaxPartitions <= 0 {
		config.MaxPartitions = DEFAULT_DDR_PARTITIONS
	}

	if config.Topic == "" {
		config.Topic = DEFAULT_DDR_TOPIC
	}

	p, err := NewKafkaProducer(&config.KafkaProducerConfig)

	if err != nil {
		return
	}

	dp = &DDRProducer{
		Producer: p,
		Config:   config,
	}
	return
}
