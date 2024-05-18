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

	if os.Args[1] == "consumer" {
		startAllConsumer(ctx)
	} else {
		produceDRScansFromFile("resolvers.txt")
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

	// Only logrus the warning severity or above.
	logrus.SetLevel(logrus.DebugLevel)
}

func produceDRScansFromFile(filePath string) {
	resolvers := []struct {
		Host string
		Port int
	}{}

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
		resolvers = append(resolvers, struct {
			Host string
			Port int
		}{
			Host: line,
			Port: 53,
		})
		// Process the line here (e.g., store in a variable, perform further operations)
	}

	if err := scanner.Err(); err != nil {
		logrus.Errorf("error during file reading: %s", err.Error())
	}

	file.Close()

	logrus.Infof("got %d resolvers", len(resolvers))

	err = producer.ProduceDDRScans(resolvers, true)
	if err != nil {
		logrus.Errorf("failed to produce DDR scan: %v", err)
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
	switch protocol {
	case "ddr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION)
		pc, err := consumer.NewKafkaDDRParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		pc.Consume(ctx)
	case "doh":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION)
		pc, err := consumer.NewKafkaDoHParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		pc.Consume(ctx)
	case "doq":
		// start the DOQ scanner
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION)
		pc, err := consumer.NewKafkaDoTParallelEventConsumer(nil, sh)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.ConcurrentConsumer)
		}
		pc.Consume(ctx)
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
		pc.Consume(ctx)
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
		pc.Consume(ctx)
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
		pc.Consume(ctx)
	}
}
