package consumer

import (
	"encoding/json"
	"errors"
	"net"
	"reflect"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DDR_CONSUMER_TOPIC = "ddr-scan"
const DEFAULT_DDR_CONSUMER_GROUP = "ddr-scan-group"
const DEFAULT_DDR_CONCURRENT_CONSUMER = 10

type DDRProcessEventHandler struct {
	EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func scheduleDoEScans(ddrScan *scan.DDRScan) {
	// schedule DoE scans
	if ddrScan.Meta.ScheduleDoEScans {
		logrus.Infof("schedule DoE scans for DDR scan %s", ddrScan.Meta.ScanId)

		if len(ddrScan.Result.Response.ResponseMsg.Answer) > 0 {
			// parse DDR response
			scans, errColl := ddrScan.CreateScansFromResponse()
			ddrScan.Meta.AddError(errColl...)

			// schedule
			for _, s := range scans {
				switch s.GetType() {
				case scan.DOH_SCAN_TYPE:
					produceScan(ddrScan, s, producer.NewDoHScanProducer)
				case scan.DOQ_SCAN_TYPE:
					produceScan(ddrScan, s, producer.NewDoQScanProducer)
				case scan.DOT_SCAN_TYPE:
					produceScan(ddrScan, s, producer.NewDoTScanProducer)
				}
			}
		} else {
			logrus.Warnf("no DoE scans to schedule since there was no SVCB answers %s", ddrScan.Meta.ScanId)
		}
	} else {
		logrus.Warnf("scheduling DoE scans for DDR scan %s disabled!", ddrScan.Meta.ScanId)
	}
}

func schedulePTRScan(ddrScan *scan.DDRScan) {
	logrus.Infof("schedule PTR scan for DDR scan %s", ddrScan.Meta.ScanId)

	// check if ddr scan was based on an IP address
	ip := net.ParseIP(ddrScan.Query.Host)

	if ip == nil {
		logrus.Warnf("DDR scan %s was not based on an IP address, no PTR scan scheduled", ddrScan.Meta.ScanId)
	} else {
		logrus.Infof("DDR scan %s was based on an IP address, schedule PTR scan", ddrScan.Meta.ScanId)
		q := query.NewPTRQuery()
		q.SetQueryMsg(ip.String())
		// TODO change to local stub
		q.Host = "8.8.8.8"

		scan, err := scan.NewPTRScan(&q.ConventionalDNSQuery, ddrScan.Meta.ScanId, ddrScan.Meta.RootScanId)
		if err != nil {
			logrus.Errorf("failed to create PTR scan: %v", err)
			ddrScan.Meta.AddError(err)
			return
		}
		producer, err := producer.NewPTRScanProducer(nil)
		if err != nil {
			logrus.Errorf("failed to create PTR scan producer: %v", err)
			ddrScan.Meta.AddError(err)
			return
		}

		err = producer.Produce(scan)
		if err != nil {
			logrus.Errorf("failed to produce PTR scan: %v", err)
			ddrScan.Meta.AddError(err)
		}
	}
}

func (ddr *DDRProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) (err error) {
	if msg == nil {
		logrus.Warn("received nil message, nothing to consume")
		return nil
	}

	ddrScan := &scan.DDRScan{}
	err = json.Unmarshal(msg.Value, ddrScan)
	if err != nil {
		logrus.Errorf("failed to unmarshal message into %s", reflect.TypeOf(ddrScan).String())
		return
	}

	logrus.Infof("received DDR scan %s of host %s with port %d", ddrScan.Meta.ScanId, ddrScan.Query.Host, ddrScan.Query.Port)

	// execute query
	ddrScan.Meta.SetStarted()
	ddrScan.Result, err = ddr.QueryHandler.Query(ddrScan.Query)
	ddrScan.Meta.SetFinished()

	if err != nil {
		logrus.Errorf("failed to query %s: %v", ddrScan.Meta.ScanId, err)
		ddrScan.Meta.AddError(err)
	} else {
		logrus.Infof(
			"successfully queried %s on host %s with port %d, received %d SVCB records",
			ddrScan.Meta.ScanId,
			ddrScan.Query.Host,
			ddrScan.Query.Port,
			len(ddrScan.Result.Response.ResponseMsg.Answer),
		)

		// produce DoE scans
		scheduleDoEScans(ddrScan)

		// produce PTR scan
		schedulePTRScan(ddrScan)
	}

	err = storage.Store(ddrScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", ddrScan.Meta.ScanId, err)
	}

	return
}

func NewKafkaDDREventConsumer(config *KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DDR_CONSUMER_GROUP
	}

	ph := &DDRProcessEventHandler{
		QueryHandler: query.NewDDRQueryHandler(),
	}

	kec, err = NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDDRParallelEventConsumer(config *KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		config = &KafkaParallelConsumerConfig{
			KafkaParallelEventConsumerConfig: &KafkaParallelEventConsumerConfig{
				ConcurrentConsumer: DEFAULT_DDR_CONCURRENT_CONSUMER,
			},
			KafkaConsumerConfig: &KafkaConsumerConfig{
				ConsumerGroup: DEFAULT_DDR_CONSUMER_GROUP,
				Server:        DEFAULT_KAFKA_SERVER,
			},
		}
		logrus.Warnf("no config provided, using default values: %v", config)
	}

	if config.KafkaConsumerConfig == nil {
		config.KafkaConsumerConfig = &KafkaConsumerConfig{
			ConsumerGroup: DEFAULT_DDR_CONSUMER_GROUP,
			Server:        DEFAULT_KAFKA_SERVER,
		}
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (EventConsumer, error) {
		return NewKafkaDDREventConsumer(
			config.KafkaConsumerConfig,
			storageHandler,
		)
	}
	kec, err = NewKafkaParallelEventConsumer(createConsumerFunc, config.KafkaParallelEventConsumerConfig)

	if err != nil {
		logrus.Errorf("failed to create parallel consumer: %v", err)
	}

	return
}

type newScanProducer func(config *producer.ProducerConfig) (sp *producer.ScanProducer, err error)

func produceScan(ddrScan *scan.DDRScan, scan scan.Scan, create newScanProducer) {
	p, err := create(nil)
	if err != nil {
		logrus.Errorf("failed to create scan producer: %v", err)
		ddrScan.Meta.AddError(err)
	}
	err = p.Produce(scan)
	if err != nil {
		logrus.Errorf("failed to produce scan: %v", err)
		ddrScan.Meta.AddError(err)
	}
	p.Close()
}
