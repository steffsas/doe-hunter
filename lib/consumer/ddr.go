package consumer

import (
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/steffsas/doe-hunter/lib/storage"
)

const DEFAULT_DDR_CONSUMER_GROUP = "ddr-scan-group"

type DDRProcessEventHandler struct {
	k.EventProcessHandler

	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (ddr *DDRProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	ddrScan := &scan.DDRScan{}
	err := json.Unmarshal(msg.Value, ddrScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DDR scan %s: %s", ddrScan.Meta.ScanId, err.Error())
		return err
	}

	// execute query
	var qErr custom_errors.DoEErrors
	ddrScan.Meta.SetStarted()
	ddrScan.Result, qErr = ddr.QueryHandler.Query(ddrScan.Query)
	ddrScan.Meta.SetFinished()

	if qErr != nil {
		if qErr.IsCritical() && !strings.Contains(qErr.Error(), custom_errors.ErrNoResponse.Error()) {
			logrus.Errorf("fatal error during DDR query %s: %v", ddrScan.Meta.ScanId, qErr.Error())
		}
		ddrScan.Meta.AddError(qErr)
	} else {
		// produce DoE scans
		scheduleDoEAndCertScans(ddrScan)

		// produce PTR scan
		schedulePTRScan(ddrScan)
	}

	err = storage.Store(ddrScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", ddrScan.Meta.ScanId, qErr.Error())
	}

	return err
}

func NewKafkaDDREventConsumer(config *k.KafkaConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DDR_CONSUMER_GROUP
	}

	ph := &DDRProcessEventHandler{
		QueryHandler: query.NewDDRQueryHandler(),
	}

	kec, err = k.NewKafkaEventConsumer(config, ph, storageHandler)

	return
}

func NewKafkaDDRParallelEventConsumer(config *k.KafkaParallelConsumerConfig, storageHandler storage.StorageHandler) (kec *k.KafkaParallelConsumer, err error) {
	if config == nil {
		config = k.GetDefaultKafkaParallelConsumerConfig(DEFAULT_DDR_CONSUMER_GROUP, k.DEFAULT_DDR_TOPIC)
	}

	if storageHandler == nil {
		return nil, errors.New("no storage handler provided")
	}

	createConsumerFunc := func() (k.EventConsumer, error) {
		return NewKafkaDDREventConsumer(
			config.KafkaConsumerConfig,
			storageHandler,
		)
	}
	kec, err = k.NewKafkaParallelEventConsumer(createConsumerFunc, config.KafkaParallelEventConsumerConfig)

	if err != nil {
		logrus.Errorf("failed to create parallel consumer: %v", err)
	}

	return
}

func produceScan(ddrScan *scan.DDRScan, scan scan.Scan, topic string) {
	p, err := producer.NewScanProducer(topic, nil)
	if err != nil {
		logrus.Errorf("failed to create scan producer: %v", err)
		ddrScan.Meta.AddError(custom_errors.NewGenericError(
			custom_errors.ErrProducerCreationFailed, true),
		)
	}
	defer p.Close()

	err = p.Produce(scan)
	if err != nil {
		logrus.Errorf("failed to produce scan: %v", err)
		ddrScan.Meta.AddError(
			custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true),
		)
	}
}

func scheduleDoEAndCertScans(ddrScan *scan.DDRScan) {
	// schedule DoE scans
	if ddrScan.Meta.ScheduleDoEScans {
		logrus.Infof("schedule DoE and certificate scans for DDR scan %s", ddrScan.Meta.ScanId)

		if len(ddrScan.Result.Response.ResponseMsg.Answer) > 0 {
			logrus.Debugf("got %d SVCB answers, schedule DoE scans", len(ddrScan.Result.Response.ResponseMsg.Answer))
			// parse DDR response
			scans, errColl := ddrScan.CreateScansFromResponse()
			ddrScan.Meta.AddError(errColl...)

			// schedule
			for _, s := range scans {
				switch s.GetType() {
				case scan.DOH_SCAN_TYPE:
					produceScan(ddrScan, s, k.DEFAULT_DOH_TOPIC)
				case scan.DOQ_SCAN_TYPE:
					produceScan(ddrScan, s, k.DEFAULT_DOQ_TOPIC)
				case scan.DOT_SCAN_TYPE:
					produceScan(ddrScan, s, k.DEFAULT_DOT_TOPIC)
				case scan.CERTIFICATE_SCAN_TYPE:
					produceScan(ddrScan, s, k.DEFAULT_CERTIFICATE_TOPIC)
				}
			}
		} else {
			logrus.Infof("no DoE scans to schedule since there was no SVCB answers %s", ddrScan.Meta.ScanId)
		}
	}
}

func schedulePTRScan(ddrScan *scan.DDRScan) {
	logrus.Infof("schedule PTR scan for DDR scan %s", ddrScan.Meta.ScanId)

	ddrScan.Meta.PTRScheduled = true

	// check if ddr scan was based on an IP address
	ip := net.ParseIP(ddrScan.Query.Host)

	if ip == nil {
		logrus.Warnf("DDR scan %s was not based on an IP address, no PTR scan scheduled", ddrScan.Meta.ScanId)
		ddrScan.Meta.PTRScheduled = false
	} else {
		logrus.Infof("DDR scan %s was based on an IP address, schedule PTR scan", ddrScan.Meta.ScanId)
		q := query.NewPTRQuery()
		q.SetQueryMsg(ip.String())
		q.QueryMsg.RecursionDesired = true
		q.Host = query.DEFAULT_RECURSIVE_RESOLVER

		ptrScan := scan.NewPTRScan(&q.ConventionalDNSQuery, ddrScan.Meta.ScanId, ddrScan.Meta.RootScanId)
		producer, cErr := producer.NewScanProducer(k.DEFAULT_PTR_TOPIC, nil)
		if cErr != nil {
			logrus.Errorf("failed to create PTR scan producer: %v", cErr.Error())
			cErr := custom_errors.NewGenericError(custom_errors.ErrProducerCreationFailed, true)
			ddrScan.Meta.AddError(cErr)
			return
		}
		defer producer.Close()

		err := producer.Produce(ptrScan)
		if err != nil {
			logrus.Errorf("failed to produce PTR scan: %v", cErr)
			cErr := custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true)
			ddrScan.Meta.AddError(cErr)
		}
	}
}
