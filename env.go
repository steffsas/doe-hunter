package main

import (
	"os"
	"slices"

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

// nolint: gochecknoglobals
var RUN_ENV = "RUN"

// nolint: gochecknoglobals
var MONGO_SERVER_ENV = "MONGO_SERVER"

// nolint: gochecknoglobals
var KAFKA_SERVER_ENV = "KAFKA_SERVER"

// nolint: gochecknoglobals
var VANTAGE_POINT_ENV = "VANTAGE_POINT"

// nolint: gochecknoglobals
var LOG_LEVEL_ENV = "LOG_LEVEL"

// nolint: gochecknoglobals
var IPV4_FILE_ENV = "IPV4_FILE"

// nolint: gochecknoglobals
var IPV4_WATCH_ENV = "IPV4_WATCH"

// nolint: gochecknoglobals
var IPV6_FILE_ENV = "IPV6_FILE"

// nolint: gochecknoglobals
var IPV6_WATCH_ENV = "IPV6_WATCH"

// nolint: gochecknoglobals
var PROTOCOL_ENV = "PROTOCOL"

// nolint: gochecknoglobals
var THREADS_ENV = "THREADS"

// nolint: gochecknoglobals
var LOCAL_ADDRESS_ENV = "LOCAL_ADDRESS"

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		logrus.Fatalf("failed to load .env file: %v", err)
	}
}

func getEnvVar(variable string) string {
	value, exists := os.LookupEnv(variable)
	if !exists {
		logrus.Fatalf("environment variable %s is missing", variable)
	} else {
		switch variable {
		case RUN_ENV:
			if !slices.Contains(SUPPORTED_RUN_TYPES, value) {
				logrus.Fatalf("unsupported run type %s", value)
				return ""
			}
		case PROTOCOL_ENV:
			if !slices.Contains(SUPPORTED_PROTOCOL_TYPES, value) {
				logrus.Fatalf("unsupported protocol type %s", value)
				return ""
			}
		}
	}
	return value
}
