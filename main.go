package main

import (
	"context"
	"os"
	"time"

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
	"ddr", "doh", "doq", "dot",
}

// nolint: gochecknoglobals
var SUPPORTED_RUN_TYPES = []string{
	"consumer", "producer",
}

func main() {
	ctx := context.Background()

	setLogger()

	// // check if protocol type is supported
	// protocolType := os.Getenv(ENV_PROTOCOL_TYPE)
	// if !slices.Contains(SUPPORTED_PROTOCOL_TYPES, protocolType) {
	// 	logrus.Fatalf("unsupported protocol type %s, must be one of %s", protocolType, SUPPORTED_PROTOCOL_TYPES)
	// 	return
	// }

	// // check if scanner type is supported
	// scannerTypeEnv := os.Getenv(ENV_RUN_TYPE)
	// if !slices.Contains(SUPPORTED_RUN_TYPES, scannerTypeEnv) {
	// 	logrus.Fatalf("unsupported run type %s, must be one of %s", scannerTypeEnv, SUPPORTED_RUN_TYPES)
	// 	return
	// }
	// isConsumer := scannerTypeEnv == "consumer"

	// // get kafka server
	// kafkaServer := os.Getenv(ENV_KAFKA_SERVER)
	// if kafkaServer == "" {
	// 	kafkaServer = DEFAULT_KAFKA_SERVER
	// }

	// // get kafka consumer group
	// kafkaConsumerGroup := os.Getenv(ENV_KAFKA_CONSUMER_GROUP)

	// // get kafka consumer group
	// parallelConsumer := 1
	// parallelConsumerEnv := os.Getenv(ENV_PARALLEL_CONSUMER)
	// if parallelConsumerEnv != "" {
	// 	var err error
	// 	parallelConsumer, err = strconv.Atoi(parallelConsumerEnv)
	// 	if err != nil {
	// 		logrus.Fatalf("failed to parse parallel consumer value %s: %v", parallelConsumerEnv, err)
	// 		return
	// 	}
	// }

	scannerTypeEnv := os.Args[1]
	isConsumer := scannerTypeEnv == "consumer"
	protocolType := "ddr"
	kafkaServer := "localhost:29092"
	kafkaConsumerGroup := "ddr-scan"
	parallelConsumer := 1

	logrus.Infof("starting %s for protocol %s with kafka server %s", scannerTypeEnv, protocolType, kafkaServer)

	switch protocolType {
	case "ddr":
		if isConsumer {
			// create the storage handler
			storageHandler := storage.NewDefaultMongoStorageHandler(ctx, "ddr-scans")

			// start the DDR consumer
			if parallelConsumer > 1 {
				logrus.Infof("starting %d parallel DDR consumers", parallelConsumer)
				cons, err := consumer.NewKafkaDDREventConsumer(
					&consumer.KafkaConsumerConfig{
						Server:        kafkaServer,
						ConsumerGroup: kafkaConsumerGroup,
					},
					storageHandler,
				)

				if err != nil {
					logrus.Fatalf("failed to create parallel consumer: %v", err)
					return
				}

				err = cons.Consume(ctx, consumer.DEFAULT_DDR_CONSUMER_TOPIC)
				if err != nil {
					logrus.Fatalf("failed to consume: %v", err)
					return
				}
				cons.Close()
			} else {
				logrus.Info("starting single DDR consumer")
				cons, err := consumer.NewKafkaDDREventConsumer(
					&consumer.KafkaConsumerConfig{
						Server:        kafkaServer,
						ConsumerGroup: kafkaConsumerGroup,
					},
					storageHandler,
				)

				if err != nil {
					logrus.Fatalf("failed to create parallel consumer: %v", err)
					return
				}

				err = cons.Consume(ctx, consumer.DEFAULT_DDR_CONSUMER_TOPIC)
				if err != nil {
					logrus.Fatalf("failed to consume: %v", err)
					return
				}
				cons.Close()
			}
		} else {
			// start the DDR producer
			config := &producer.DDRProducerConfig{
				KafkaProducerConfig: producer.KafkaProducerConfig{
					Server:  kafkaServer,
					Timeout: 5 * time.Millisecond,
					Acks:    "1",
				},
				Topic:         producer.DEFAULT_DDR_TOPIC,
				MaxPartitions: 1,
			}
			producer, err := producer.NewDDRProducer(config)
			if err != nil {
				logrus.Fatalf("failed to create DDR producer: %v", err)
				return
			}
			producer.Produce()
			producer.Close()
		}
	case "doh":
		// start the DOH scanner
		logrus.Fatal("DOH not implemented yet")
	case "doq":
		// start the DOQ scanner
		logrus.Fatal("DOQ not implemented yet")
	case "dot":
		// start the DOT scanner
		logrus.Fatal("DOT not implemented yet")
	default:
		logrus.Fatalf("unsupported protocol type %s, must be one of %s", protocolType, SUPPORTED_PROTOCOL_TYPES)
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
