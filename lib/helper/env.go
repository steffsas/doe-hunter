package helper

import (
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
)

// nolint: gochecknoglobals
var SUPPORTED_PROTOCOL_TYPES = []string{
	"ddr", "doh", "doq", "dot", "certificate", "ptr", "edsr", "all",
}

// nolint: gochecknoglobals
var SUPPORTED_RUN_TYPES = []string{
	"consumer", "producer",
}

// COMMON ENVIRONMENT VARIABLES

// nolint: gochecknoglobals
var RUN_ENV = "RUN"

// nolint: gochecknoglobals
var PROTOCOL_ENV = "PROTOCOL"

// nolint: gochecknoglobals
var MONGO_SERVER_ENV = "MONGO_SERVER"

// nolint: gochecknoglobals
var KAFKA_SERVER_ENV = "KAFKA_SERVER"

// nolint: gochecknoglobals
var VANTAGE_POINT_ENV = "VANTAGE_POINT"

// nolint: gochecknoglobals
var LOG_LEVEL_ENV = "LOG_LEVEL"

// PRODUCER ENVIRONMENT VARIABLES

// nolint: gochecknoglobals
var PRODUCER_WATCH_DIRECTORY = "PRODUCER_WATCH_DIRECTORY"

// CONSUMER ENVIRONMENT VARIABLES

// nolint: gochecknoglobals
var THREADS_ENV = "THREADS"

// nolint: gochecknoglobals
var LOCAL_ADDRESS_ENV = "LOCAL_ADDRESS"

// threads
// nolint: gochecknoglobals
var THREADS_DDR_ENV = "THREADS_DDR"

// nolint: gochecknoglobals
var THREADS_EDSR_ENV = "THREADS_EDSR"

// nolint: gochecknoglobals
var THREADS_DOH_ENV = "THREADS_DOH"

// nolint: gochecknoglobals
var THREADS_DOQ_ENV = "THREADS_DOQ"

// nolint: gochecknoglobals
var THREADS_DOT_ENV = "THREADS_DOT"

// nolint: gochecknoglobals
var THREADS_CERTIFICATE_ENV = "THREADS_CERTIFICATE"

// nolint: gochecknoglobals
var THREADS_PTR_ENV = "THREADS_PTR"

func LoadEnv(filepath string) error {
	if err := godotenv.Load(filepath); err != nil {
		logrus.Errorf("failed to load .env file: %v", err)
		return err
	}
	return nil
}

func GetEnvVar(variable string, requireNotEmpty bool) (string, error) {
	value, exists := os.LookupEnv(variable)
	if !exists && requireNotEmpty {
		logrus.Errorf("environment variable %s is missing", variable)
		return "", fmt.Errorf("environment variable %s is missing", variable)
	} else {
		switch variable {
		case RUN_ENV:
			if !slices.Contains(SUPPORTED_RUN_TYPES, value) {
				logrus.Errorf("unsupported run type %s", value)
				return "", fmt.Errorf("unsupported run type %s", value)
			}
		case PROTOCOL_ENV:
			if !slices.Contains(SUPPORTED_PROTOCOL_TYPES, value) {
				logrus.Errorf("unsupported protocol type %s", value)
				return "", fmt.Errorf("unsupported protocol type %s", value)
			}
		}
	}
	return value, nil
}

func GetThreads(protocol string) (int, error) {
	commonThreads, _ := GetEnvVar(THREADS_ENV, false)
	protocolThreads, _ := GetEnvVar(protocol, false)

	if protocolThreads != "" {
		threads, err := strconv.Atoi(protocolThreads)
		if err != nil {
			logrus.Errorf("invalid number of threads %s", protocolThreads)
			return 0, err
		}
		return threads, nil
	} else if commonThreads != "" {
		threads, err := strconv.Atoi(commonThreads)
		if err != nil {
			logrus.Errorf("invalid number of threads %s", commonThreads)
			return 0, err
		}
		return threads, nil
	}

	logrus.Errorf("number of threads not set for protocol %s", protocol)
	return 0, fmt.Errorf("number of threads not set for protocol %s", protocol)
}
