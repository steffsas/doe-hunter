package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

// the type of the scanner (e.g. consumer, producer)
const ENV_RUN_TYPE = "DOE_RUN_TYPE"

// the protocol to be considered (e.g. ddr, doh, doq, dot)
const ENV_PROTOCOL_TYPE = "DOE_PROTOCOL_TYPE"

// if set, the consumer will use this kafka server, otherwise localhost:9092 is used
const ENV_KAFKA_SERVER = "DOE_KAFKA_SERVER"

// if set, the consumer will use this consumer group (defaults to the consumer/producer's default settings otherwise)
const ENV_KAFKA_CONSUMER_GROUP = "DOE_KAFKA_CONSUMER_GROUP"

// if set to a value >= 1, multiple consumers will be started (optional, defaults to 1)
const ENV_PARALLEL_CONSUMER = "DOE_PARALLEL_CONSUMER"

const DEFAULT_KAFKA_SERVER = "localhost:29092"
const DEFAULT_PARALLEL_CONSUMER = 1 // no parallelism

// nolint: gochecknoglobals
var SUPPORTED_PROTOCOL_TYPES = []string{
	"ddr", "doh", "doq", "dot", "certificate", "ptr",
}

// nolint: gochecknoglobals
var SUPPORTED_RUN_TYPES = []string{
	"consumer", "producer",
}

// var (
// 	scanType         = flag.String("scanType", "consumer", "consumer or producer")
// 	protocol         = flag.String("protocol", "ddr", "protocol type (ddr, doh, doq, dot, certificate, ptr)")
// 	parallelConsumer = flag.Int("parallelConsumer", 1, "number of parallel consumers")
// )

const DDR_CONSUMER = 100

func main() {
	logrus.SetLevel(logrus.WarnLevel)
	ctx := context.Background()

	// flag.Parse()

	setLogger()

	if os.Args[1] == "consumer" {
		startAllConsumer(ctx)
		// startConsumer(ctx, "ddr")
	} else {
		_ = produceDDRScansFromCensys("data/censys_100k.json", true)
	}
}

func setLogger() {
	customFormatter := new(logrus.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.FullTimestamp = true
	customFormatter.PadLevelText = true
	customFormatter.ForceColors = true
	logrus.SetFormatter(customFormatter)

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	logrus.SetOutput(os.Stdout)
}

type CensysData struct {
	Ipv4             string  `json:"ipv4"`
	Ipv6             string  `json:"ipv6"`
	Dns_version      string  `json:"dns_version"`
	Dns_server_type  string  `json:"dns_server_type"`
	Continent        string  `json:"continent"`
	Country          string  `json:"country"`
	City             string  `json:"city"`
	Country_code     string  `json:"country_code"`
	Latitude         float32 `json:"latitude"`
	Longitude        float32 `json:"longitude"`
	Asn              string  `json:"asn"`
	Asn_name         string  `json:"asn_name"`
	Asn_country_code string  `json:"asn_country_code"`
	Os_id            string  `json:"os_id"`
	Os_vendor        string  `json:"os_vendor"`
	Os_product       string  `json:"os_product"`
	Os_version       string  `json:"os_version"`
}

func produceDDRScansFromCensys(filePath string, scheduleDoEScans bool) error {
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
	censysData := []CensysData{}
	for _, line := range contentSplit {
		c := &CensysData{}
		if err := json.Unmarshal([]byte(line), c); err != nil {
			logrus.Errorf("failed to unmarshal json: %v, %s", err, line)
			return err
		}
		censysData = append(censysData, *c)
	}

	logrus.Infof("got %d resolvers from censys data", len(censysData))

	// create a new producer
	config := producer.GetDefaultKafkaProducerConfig()
	config.MaxPartitions = DDR_CONSUMER
	p, err := producer.NewScanProducer(kafka.DEFAULT_DDR_TOPIC, config)

	if err != nil {
		logrus.Errorf("failed to create DDR producer: %v", err)
		return err
	}
	defer p.Close()

	wg := sync.WaitGroup{}

	ipv4Considered := []string{}
	ipv6Considered := []string{}

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
				scan := scan.NewDDRScan(q, scheduleDoEScans)
				fillCensysMetaInformation(scan, res)

				wg.Add(1)
				go scheduleScan(scan, p, &wg)
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
				scan := scan.NewDDRScan(q, scheduleDoEScans)
				fillCensysMetaInformation(scan, res)

				wg.Add(1)
				go scheduleScan(scan, p, &wg)
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

	p.Close()

	return nil
}

func fillCensysMetaInformation(scan *scan.DDRScan, c CensysData) {
	scan.Meta.DNSVersion = c.Dns_version
	scan.Meta.DNSServerType = c.Dns_server_type
	scan.Meta.Continent = c.Continent
	scan.Meta.Country = c.Country
	scan.Meta.City = c.City
	scan.Meta.CountryCode = c.Country_code
	scan.Meta.Latitude = c.Latitude
	scan.Meta.Longitude = c.Longitude
	scan.Meta.ASN = c.Asn
	scan.Meta.ASNName = c.Asn_name
	scan.Meta.ASNCountryCode = c.Asn_country_code
	scan.Meta.OSId = c.Os_id
	scan.Meta.OSVendor = c.Os_vendor
	scan.Meta.OSProduct = c.Os_product
	scan.Meta.OSVersion = c.Os_version
}

func scheduleScan(scan *scan.DDRScan, p *producer.ScanProducer, wg *sync.WaitGroup) {
	defer wg.Done()
	// produce the scan
	if err := p.Produce(scan); err != nil {
		logrus.Errorf("failed to produce DDR scan: %v", err)
	}
}

// func produceDRScansFromTXTFile(filePath string) {
// 	resolvers := []struct {
// 		Host string
// 		Port int
// 	}{}

// 	// Open the file
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		logrus.Errorf("failed to open file: %v", err)
// 		return
// 	}

// 	// Create a new scanner
// 	scanner := bufio.NewScanner(file)

// 	// Loop through lines
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		resolvers = append(resolvers, struct {
// 			Host string
// 			Port int
// 		}{
// 			Host: line,
// 			Port: 53,
// 		})
// 		// Process the line here (e.g., store in a variable, perform further operations)
// 	}

// 	if err := scanner.Err(); err != nil {
// 		logrus.Errorf("error during file reading: %s", err.Error())
// 	}

// 	file.Close()

// 	logrus.Infof("got %d resolvers", len(resolvers))

// 	err = ProduceDDRScans(resolvers, true)
// 	if err != nil {
// 		logrus.Errorf("failed to produce DDR scan: %v", err)
// 	}
// }

func startAllConsumer(ctx context.Context) {
	wg := sync.WaitGroup{}

	for _, protocol := range SUPPORTED_PROTOCOL_TYPES {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			startConsumer(ctx, p)
		}(protocol)
	}

	wg.Wait()
}

func startConsumer(ctx context.Context, protocol string) {
	switch protocol {
	case "ddr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION)
		config := kafka.GetDefaultKafkaParallelConsumerConfig(consumer.DEFAULT_DDR_CONSUMER_GROUP, kafka.DEFAULT_DDR_TOPIC)
		config.ConcurrentConsumer = DDR_CONSUMER
		pc, err := consumer.NewKafkaDDRParallelEventConsumer(config, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		_ = pc.Consume(ctx)
	case "doh":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION)
		pc, err := consumer.NewKafkaDoHParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		_ = pc.Consume(ctx)
	case "doq":
		// start the DOQ scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION)
		pc, err := consumer.NewKafkaDoQParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		_ = pc.Consume(ctx)
	case "dot":
		// start the DOT scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION)
		pc, err := consumer.NewKafkaDoTParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		_ = pc.Consume(ctx)
	case "ptr":
		// start the PTR scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION)
		pc, err := consumer.NewKafkaPTRParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		_ = pc.Consume(ctx)
	case "certificate":
		// start the PTR scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION)
		pc, err := consumer.NewKafkaCertificateParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		_ = pc.Consume(ctx)
	}
}

func ProduceDDRScans(resolvers []struct {
	Host string
	Port int
}, scheduleDoEScans bool) error {
	// create a new producer
	// create a new producer
	p, err := producer.NewScanProducer(kafka.DEFAULT_DDR_TOPIC, nil)

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
