package kafka

import "time"

const DEFAULT_KAFKA_SERVER = "localhost:29092"
const DEFAULT_KAFKA_CONSUMER_GROUP = "default-consumer-group"

const DEFAULT_KAFKA_READ_TIMEOUT = 5000 * time.Millisecond

const DEFAULT_DOT_TOPIC = "dot-scan"
const DEFAULT_DOQ_TOPIC = "doq-scan"
const DEFAULT_DDR_TOPIC = "ddr-scan"
const DEFAULT_PTR_TOPIC = "ptr-scan"
const DEFAULT_DOH_TOPIC = "doh-scan"
const DEFAULT_CERTIFICATE_TOPIC = "certificate-scan"

const DEFAULT_CONCURRENT_CONSUMER = 10
const DEFAULT_PARTITIONS = 100
