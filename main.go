package main

import (
	"bufio"
	"context"
	"flag"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/consumer"
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
var (
	scanType         = flag.String("scanType", "consumer", "consumer or producer")
	protocol         = flag.String("protocol", "ddr", "protocol type (ddr, doh, doq, dot, certificate, ptr)")
	parallelConsumer = flag.Int("parallelConsumer", 1, "number of parallel consumers")
)

func main() {
	ctx := context.Background()

	// flag.Parse()

	setLogger()

	// logrus.Infof("starting %s for protocol %s with kafka server %s", *scanType, *protocol, consumer.DEFAULT_KAFKA_SERVER)
	// if isConsumer(*scanType) {
	// 	logrus.Infof("starting %d parallel consumers", *parallelConsumer)
	// }

	if os.Args[1] == "consumer" {
		startAllConsumer(ctx)
	} else {
		produceDRScansFromFile("resolvers.txt")
	}

	// consumerConfig := &consumer.KafkaParallelConsumerConfig{
	// 	KafkaParallelEventConsumerConfig: &consumer.KafkaParallelEventConsumerConfig{
	// 		ConcurrentConsumer: *parallelConsumer,
	// 	},
	// }

	// switch *protocol {
	// case "ddr":
	// 	if isConsumer(*scanType) {
	// 		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION)
	// 		pc, err := consumer.NewKafkaDDRParallelEventConsumer(consumerConfig, sh)
	// 		if err != nil {
	// 			logrus.Fatalf("failed to create parallel consumer: %v", err)
	// 			return
	// 		}
	// 		pc.Consume(ctx, consumer.DEFAULT_DDR_CONSUMER_TOPIC)
	// 	} else {
	// 		// start the DDR producer
	// 		produceDRScansFromFile("resolvers.txt")
	// 	}
	// case "doh":
	// 	// start the DOH scanner
	// 	if isConsumer(*scanType) {
	// 		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION)
	// 		pc, err := consumer.NewKafkaDoHParallelEventConsumer(consumerConfig, sh)
	// 		if err != nil {
	// 			logrus.Fatalf("failed to create parallel consumer: %v", err)
	// 			return
	// 		}
	// 		pc.Consume(ctx, consumer.DEFAULT_DOH_CONSUMER_TOPIC)
	// 	} else {
	// 		logrus.Fatal("DoH producer not implemented yet")
	// 	}
	// case "doq":
	// 	// start the DOQ scanner
	// 	if isConsumer(*scanType) {
	// 		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION)
	// 		pc, err := consumer.NewKafkaDoTParallelEventConsumer(consumerConfig, sh)
	// 		if err != nil {
	// 			logrus.Fatalf("failed to create parallel consumer: %v", err)
	// 			return
	// 		}
	// 		pc.Consume(ctx, consumer.DEFAULT_DOQ_CONSUMER_TOPIC)
	// 	} else {
	// 		logrus.Fatal("DoQ producer not implemented yet")
	// 	}
	// case "dot":
	// 	// start the DOT scanner
	// 	if isConsumer(*scanType) {
	// 		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION)
	// 		pc, err := consumer.NewKafkaDoTParallelEventConsumer(consumerConfig, sh)
	// 		if err != nil {
	// 			logrus.Fatalf("failed to create parallel consumer: %v", err)
	// 			return
	// 		}
	// 		pc.Consume(ctx, consumer.DEFAULT_DOT_CONSUMER_TOPIC)
	// 	} else {
	// 		logrus.Fatal("DoH producer not implemented yet")
	// 	}
	// case "ptr":
	// 	// start the PTR scanner
	// 	if isConsumer(*scanType) {
	// 		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION)
	// 		pc, err := consumer.NewKafkaPTRParallelEventConsumer(consumerConfig, sh)
	// 		if err != nil {
	// 			logrus.Fatalf("failed to create parallel consumer: %v", err)
	// 			return
	// 		}
	// 		pc.Consume(ctx, consumer.DEFAULT_PTR_CONSUMER_TOPIC)
	// 	} else {
	// 		logrus.Fatal("DoH producer not implemented yet")
	// 	}
	// case "certificate":
	// 	// start the PTR scanner
	// 	if isConsumer(*scanType) {
	// 		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION)
	// 		pc, err := consumer.NewKafkaCertificateParallelEventConsumer(consumerConfig, sh)
	// 		if err != nil {
	// 			logrus.Fatalf("failed to create parallel consumer: %v", err)
	// 			return
	// 		}
	// 		pc.Consume(ctx, consumer.DEFAULT_CERTIFICATE_CONSUMER_TOPIC)
	// 	} else {
	// 		logrus.Fatal("DoH producer not implemented yet")
	// 	}
	// default:
	// 	logrus.Fatalf("unsupported protocol type %s, must be one of %s", *protocol, SUPPORTED_PROTOCOL_TYPES)
	// }
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

	// Only logrus the warning severity or above.
	logrus.SetLevel(logrus.DebugLevel)
}

func produceDRScansFromFile(filePath string) {
	resolvers := []string{}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		logrus.Errorf("failed to open file: %v", err)
		return
	}

	// Create a new scanner
	scanner := bufio.NewScanner(file)

	// Loop through lines
	for scanner.Scan() {
		line := scanner.Text()
		resolvers = append(resolvers, line)
		// Process the line here (e.g., store in a variable, perform further operations)
	}

	if err := scanner.Err(); err != nil {
		logrus.Errorf("error during file reading: %s", err.Error())
	}

	file.Close()

	// create producer
	p, err := producer.NewDDRScanProducer(nil)
	if err != nil {
		logrus.Errorf("failed to create producer: %s", err.Error())
		return
	}
	defer p.Close()

	for _, res := range resolvers {
		// create query
		q := query.NewDDRQuery()
		q.Host = res
		q.AutoFallbackTCP = true
		q.Protocol = query.DNS_TCP
		q.Port = query.DEFAULT_DNS_PORT

		// create the scan
		s := scan.NewDDRScan(q, true)
		p.Produce(s)
	}
}

func isConsumer(scanType string) bool {
	return scanType == "consumer"
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
	consumerConfig := &consumer.KafkaParallelConsumerConfig{
		KafkaParallelEventConsumerConfig: &consumer.KafkaParallelEventConsumerConfig{
			ConcurrentConsumer: 1,
		},
	}

	switch protocol {
	case "ddr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION)
		pc, err := consumer.NewKafkaDDRParallelEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		}
		pc.Consume(ctx, consumer.DEFAULT_DDR_CONSUMER_TOPIC)
	case "doh":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION)
		pc, err := consumer.NewKafkaDoHParallelEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		}
		pc.Consume(ctx, consumer.DEFAULT_DOH_CONSUMER_TOPIC)
	case "doq":
		// start the DOQ scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION)
		pc, err := consumer.NewKafkaDoTParallelEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		}
		pc.Consume(ctx, consumer.DEFAULT_DOQ_CONSUMER_TOPIC)
	case "dot":
		// start the DOT scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION)
		pc, err := consumer.NewKafkaDoTParallelEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		}
		pc.Consume(ctx, consumer.DEFAULT_DOT_CONSUMER_TOPIC)
	case "ptr":
		// start the PTR scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION)
		pc, err := consumer.NewKafkaPTRParallelEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		}
		pc.Consume(ctx, consumer.DEFAULT_PTR_CONSUMER_TOPIC)
	case "certificate":
		// start the PTR scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION)
		pc, err := consumer.NewKafkaCertificateParallelEventConsumer(consumerConfig, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		}
		pc.Consume(ctx, consumer.DEFAULT_CERTIFICATE_CONSUMER_TOPIC)
	}
}
