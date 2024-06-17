package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

func main() {
	ctx := context.Background()

	err := godotenv.Load()
	if err != nil {
		logrus.Fatalf("failed to load .env file: %v", err)
	}

	setLogger()

	if *exec == "consumer" {
		switch getEnvVar() {
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
	switch *logLevel {
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

func scheduleDDRScan(s scan.Scan, p producer.ScanProducer, wg *sync.WaitGroup) {
	defer wg.Done()
	// produce scan
	if err := p.Produce(s, consumer.GetKafkaVPTopic(kafka.DEFAULT_DDR_TOPIC, *vantagePoint)); err != nil {
		logrus.Errorf("failed to produce DDR scan: %v", err)
	}
}

func startAllConsumer(ctx context.Context) {
	wg := sync.WaitGroup{}

	for _, protocol := range SUPPORTED_PROTOCOL_TYPES {
		if protocol == "all" {
			continue
		}
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

	var queryConfig *query.QueryConfig
	if localAddr != nil && *localAddr != "" {
		localIpAddr := net.ParseIP(*localAddr)
		if localIpAddr == nil {
			logrus.Fatalf("invalid local address %s", *localAddr)
			return
		}

		queryConfig = &query.QueryConfig{
			LocalAddr: localIpAddr,
		}
	}

	config := producer.GetDefaultKafkaProducerConfig()
	if kakfaServer != nil {
		config.Server = *kakfaServer
	}
	prod, err := producer.NewKafkaScanProducer(config)
	if err != nil {
		logrus.Fatalf("failed to create producer: %v", err)
		return
	}
	defer prod.Close()

	switch protocol {
	case "ddr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION, *mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DDR_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DDR_CONSUMER_GROUP

		//nolint:contextcheck
		pc, err := consumer.NewKafkaDDREventConsumer(consumerConfig, prod, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "doh":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION, *mongoServer)

		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOH_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOH_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDoHEventConsumer(consumerConfig, prod, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "doq":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION, *mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOQ_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOQ_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDoQEventConsumer(consumerConfig, prod, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "dot":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION, *mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOT_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOT_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaDoTEventConsumer(consumerConfig, prod, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "ptr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION, *mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_PTR_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_PTR_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaPTREventConsumer(consumerConfig, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "edsr":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_EDSR_COLLECTION, *mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_EDSR_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_EDSR_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaEDSREventConsumer(consumerConfig, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "certificate":
		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION, *mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  *kakfaServer,
			Threads: *threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_CERTIFICATE_TOPIC, *vantagePoint)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_CERTIFICATE_CONSUMER_GROUP
		//nolint:contextcheck
		pc, err := consumer.NewKafkaCertificateEventConsumer(consumerConfig, sh, queryConfig)
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
