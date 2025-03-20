package main

import (
	"context"
	"net"
	"os"
	"strings"
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
	// enable if you do want to profile the application
	// f, perr := os.Create("/data/cpu.pprof")
	// if perr != nil {
	// 	logrus.Fatal(perr)
	// }
	// pprof.StartCPUProfile(f)
	// defer pprof.StopCPUProfile()
	// go http.ListenAndServe(":8088", nil)

	ctx := context.Background()

	// load environment variables and settings
	err := helper.LoadEnv("default.env")
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

	vp, err := helper.GetEnvVar(helper.VANTAGE_POINT_ENV, true)
	if err != nil {
		return
	}

	// load blocklist
	err = helper.InitBlocklist()
	if err != nil {
		logrus.Fatalf("failed to load blocklist: %v", err)
		return
	}

	if toRun == "consumer" {
		switch toRun {
		case "all":
			startAllConsumer(ctx, vp)
		default:
			protocolToRun, err := helper.GetEnvVar(helper.PROTOCOL_ENV, true)
			if err != nil {
				return
			}
			startConsumer(ctx, protocolToRun, vp)
		}
	} else {
		ipVersion, err := helper.GetEnvVar(helper.IP_VERSION_ENV, true)
		if err != nil {
			return
		}

		dirToWatch, _ := helper.GetEnvVar(helper.PRODUCER_WATCH_DIRECTORY, false)
		produceFromFile, _ := helper.GetEnvVar(helper.PRODUCER_FROM_FILE, false)

		if dirToWatch != "" {
			// let's start a producer that watches a directory for file creations and tailing
			startWatchDirectoryProducer(ctx, producer.GetProducibleScansFactory(vp, ipVersion), dirToWatch)
			return
		}
		if produceFromFile != "" {
			// let's start a producer that reads from a file
			startProducerFromFile(producer.GetProducibleScansFactory(vp, ipVersion), produceFromFile)
			return
		}

		logrus.Fatal("either specify a directory to watch or a file to read from")
	}
}

func setLogger() {
	logLevel, _ := helper.GetEnvVar(helper.LOG_LEVEL_ENV, false)

	switch strings.ToLower(logLevel) {
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

func startProducerFromFile(newScans producer.GetProducibleScans, file string) {
	sp, err := producer.NewKafkaScanProducer(producer.GetDefaultKafkaProducerConfig())
	if err != nil {
		logrus.Fatalf("failed to create producer: %v", err)
		return
	}
	p := producer.NewFileProducer(newScans, sp)

	err = p.Produce(file)
	if err != nil {
		logrus.Fatalf("failed to produce from file: %v", err)
	}
}

func startWatchDirectoryProducer(ctx context.Context, newScans producer.GetProducibleScans, dir string) {
	newProducer := func() (producer.ScanProducer, error) {
		return producer.NewKafkaScanProducer(producer.GetDefaultKafkaProducerConfig())
	}

	logrus.Infof("start watching directory %s to produce DDR scans", dir)

	p := producer.NewWatchDirectoryProducer(newScans, newProducer)
	err := p.WatchAndProduce(ctx, dir)
	if err != nil {
		logrus.Fatalf("failed to watch and produce: %v", err)
	}
}

func startAllConsumer(ctx context.Context, vp string) {
	wg := sync.WaitGroup{}

	for _, protocol := range helper.SUPPORTED_PROTOCOL_TYPES {
		if protocol == "all" {
			continue
		}
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			startConsumer(ctx, p, vp)
		}(protocol)
	}

	wg.Wait()
}

func startConsumer(ctx context.Context, protocol, vp string) {
	var queryConfig *query.QueryConfig

	kafkaServer, err := helper.GetEnvVar(helper.KAFKA_SERVER_ENV, true)
	if err != nil {
		return
	}

	mongoServer, err := helper.GetEnvVar(helper.MONGO_SERVER_ENV, true)
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

	consumerConfig := &consumer.KafkaConsumerConfig{
		Server:  kafkaServer,
		Timeout: kafka.DEFAULT_KAFKA_READ_TIMEOUT,
	}

	switch protocol {
	case "ddr":
		threads, err := helper.GetThreads(helper.THREADS_DDR_ENV)
		if err != nil {
			return
		}

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DDR_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_COLLECTION, mongoServer)

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

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_DOH_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOH_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOH_COLLECTION, mongoServer)

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

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_DOQ_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOQ_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOQ_COLLECTION, mongoServer)

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

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_DOT_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DOT_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DOT_COLLECTION, mongoServer)

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

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_PTR_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_PTR_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_PTR_COLLECTION, mongoServer)

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

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_EDSR_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_EDSR_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_EDSR_COLLECTION, mongoServer)

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

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_CERTIFICATE_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_CERTIFICATE_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CERTIFICATE_COLLECTION, mongoServer)

		//nolint:contextcheck
		pc, err := consumer.NewKafkaCertificateEventConsumer(consumerConfig, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "fingerprint":
		threads, err := helper.GetThreads(helper.THREADS_FINGERPRINT_ENV)
		if err != nil {
			return
		}

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_FINGERPRINT_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_FINGERPRINT_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_FINGERPRINT_COLLECTION, mongoServer)

		//nolint:contextcheck
		pc, err := consumer.NewKafkaFingerprintEventConsumer(consumerConfig, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "ddr-dnssec":
		threads, err := helper.GetThreads(helper.THREADS_DDR_DNSSEC_ENV)
		if err != nil {
			return
		}

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_DNSSEC_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_DDR_DNSSEC_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_DDR_DNSSEC_COLLECTION, mongoServer)

		//nolint:contextcheck
		pc, err := consumer.NewKafkaDDRDNSSECEventConsumer(consumerConfig, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "canary":
		threads, err := helper.GetThreads(helper.THREADS_CANARY_ENV)
		if err != nil {
			return
		}

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_CANARY_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_CANARAY_COLLECTION, mongoServer)

		//nolint:contextcheck
		pc, err := consumer.NewKafkaDDREventConsumer(consumerConfig, prod, sh, queryConfig)
		if err != nil {
			logrus.Fatalf("failed to create parallel consumer: %v", err)
			return
		} else {
			logrus.Infof("created parallel consumer %s with %d parallel consumers", protocol, pc.Config.Threads)
		}
		_ = pc.Consume(ctx)
	case "resinfo":
		threads, err := helper.GetThreads(helper.THREADS_RESINFO_ENV)
		if err != nil {
			return
		}

		consumerConfig.Threads = threads
		consumerConfig.Topic = helper.GetTopicFromNameAndVP(kafka.DEFAULT_RESINFO_TOPIC, vp)
		consumerConfig.ConsumerGroup = consumer.DEFAULT_RESINFO_CONSUMER_GROUP

		sh := storage.NewDefaultMongoStorageHandler(ctx, storage.DEFAULT_RESINFO_COLLECTION, mongoServer)

		//nolint:contextcheck
		pc, err := consumer.NewKafkaResInfoEventConsumer(consumerConfig, sh, queryConfig)
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
