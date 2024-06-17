package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/storage"
)

func main() {
	ctx := context.Background()

	// load environment variables and settings
	err := helper.LoadEnv(".env")
	if err != nil {
		return
	}

	// prepare logger
	setLogger()

	// get run type
	toRun, err := helper.GetEnvVar(helper.RUN_ENV, true)
	if err != nil {
		return
	}

	protocolToRun, err := helper.GetEnvVar(helper.PROTOCOL_ENV, true)
	if err != nil {
		return
	}

	if toRun == "consumer" {
		switch toRun {
		case "all":
			startAllConsumer(ctx)
		default:
			startConsumer(ctx, toRun)
		}
	} else {
		if protocolToRun == "ddr" {
			// do smth nice
		} else {
			logrus.Fatalf("unsupported protocol type %s", protocolToRun)
		}
	}
}

func setLogger() {
	logLevel, _ := helper.GetEnvVar(helper.LOG_LEVEL_ENV, false)

	switch logLevel {
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

func startAllConsumer(ctx context.Context) {
	wg := sync.WaitGroup{}

	for _, protocol := range helper.SUPPORTED_PROTOCOL_TYPES {
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
	var queryConfig *query.QueryConfig

	kafkaServer, err := helper.GetEnvVar(helper.KAFKA_SERVER_ENV, true)
	if err != nil {
		return
	}

	mongoServer, err := helper.GetEnvVar(helper.MONGO_SERVER_ENV, true)
	if err != nil {
		return
	}

	vantagePoint, err := helper.GetEnvVar(helper.VANTAGE_POINT_ENV, true)
	if err != nil {
		return
	}

	localAddr, _ := helper.GetEnvVar(helper.LOCAL_ADDRESS_ENV, false)

	if localAddr != "" {
		localIpAddr := net.ParseIP(localAddr)
		if localIpAddr == nil {
			logrus.Fatalf("invalid local address %s", localAddr)
			return
		}

		queryConfig = &query.QueryConfig{
			LocalAddr: localIpAddr,
		}
	}

	config := producer.GetDefaultKafkaProducerConfig()
	config.Server = kafkaServer

	prod, err := producer.NewKafkaScanProducer(config)
	if err != nil {
		logrus.Fatalf("failed to create producer: %v", err)
		return
	}
	defer prod.Close()

	switch protocol {
	case "ddr":
		threads, err := helper.GetThreads(helper.THREADS_DDR_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION, mongoServer)

		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DDR_TOPIC, vantagePoint)
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
		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION, mongoServer)

		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOH_TOPIC, vantagePoint)
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
		threads, err := helper.GetThreads(helper.THREADS_DOQ_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION, mongoServer)

		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOQ_TOPIC, vantagePoint)
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
		threads, err := helper.GetThreads(helper.THREADS_DOT_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION, mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_DOT_TOPIC, vantagePoint)
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
		threads, err := helper.GetThreads(helper.THREADS_PTR_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION, mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_PTR_TOPIC, vantagePoint)
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
		threads, err := helper.GetThreads(helper.THREADS_EDSR_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_EDSR_COLLECTION, mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_EDSR_TOPIC, vantagePoint)
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
		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		if err != nil {
			return
		}

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION, mongoServer)

		// remove later
		consumerConfig := &consumer.KafkaConsumerConfig{
			Server:  kafkaServer,
			Threads: threads,
		}

		consumerConfig.Topic = fmt.Sprintf("%s-%s", kafka.DEFAULT_CERTIFICATE_TOPIC, vantagePoint)
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
