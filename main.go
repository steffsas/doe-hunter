package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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

// nolint: gochecknoglobals
var SUPPORTED_PROTOCOL_TYPES = []string{
	"ddr", "doh", "doq", "dot", "certificate", "ptr", "all",
}

// nolint: gochecknoglobals
var SUPPORTED_RUN_TYPES = []string{
	"consumer", "producer",
}

// nolint: gochecknoglobals
var (
	exec             = flag.String("exec", "consumer", "consumer or producer")
	protocol         = flag.String("protocol", "ddr", "protocol type (ddr, doh, doq, dot, certificate, ptr, all)")
	threads          = flag.Int("threads", consumer.DEFAULT_CONCURRENT_THREADS, "number of threads used for consuming scan tasks")
	kakfaServer      = flag.String("kafkaServer", kafka.DEFAULT_KAFKA_SERVER, "kafka server address")
	mongoServer      = flag.String("mongoServer", storage.DEFAULT_MONGO_URL, "mongo server address")
	vantagePoint     = flag.String("vantagePoint", "default", "vantage point name, used for meta data of scan and kafka topics")
	debugLevel       = flag.String("debugLevel", "info", "debug level (trace, debug, info, warn, error, fatal, panic)")
	producerFilePath = flag.String("producerFilePath", "data/censys_100k.json", "file path to the producer file to produce ddr scans")
)

func main() {
	ctx := context.Background()

	flag.Parse()

	setLogger()

	if *exec == "consumer" {
		switch *protocol {
		case "all":
			startAllConsumer(ctx)
		default:
			startConsumer(ctx, *protocol)
		}
	} else {
		if *protocol == "ddr" {
			if err := produceDDRScansFromCensys(*producerFilePath, true); err != nil {
				logrus.Fatalf("failed to produce DDR scans: %v", err)
			}
		} else {
			logrus.Fatalf("unsupported protocol type %s", *protocol)
		}
	}
}

func setLogger() {
	switch *debugLevel {
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}

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
	p, err := producer.NewScanProducer(consumer.GetKafkaVPTopic(kafka.DEFAULT_DDR_TOPIC, *vantagePoint), config)

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
				scan := scan.NewDDRScan(q, scheduleDoEScans, *vantagePoint)
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
				scan := scan.NewDDRScan(q, scheduleDoEScans, *vantagePoint)
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
	if vantagePoint == nil || *vantagePoint == "" {
		logrus.Fatalf("vantage point name is missing")
		return
	}

	consumerConfig := &consumer.KafkaConsumerConfig{
		Server:  *kakfaServer,
		Threads: *threads,
	}

	switch protocol {
	case "ddr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION, *mongoServer)

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DDR_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DDR_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDDREventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "doh":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION, *mongoServer)

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOH_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOH_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDoHEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "doq":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION, *mongoServer)

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOQ_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOQ_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDoQEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "dot":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION, *mongoServer)

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOT_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOT_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDoTEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "ptr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION, *mongoServer)

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_PTR_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_PTR_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaPTREventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "certificate":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION, *mongoServer)

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_CERTIFICATE_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_CERTIFICATE_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaCertificateEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	default:
		logrus.Fatalf("unsupported protocol type %s", protocol)
	}
}
