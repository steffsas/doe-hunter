package consumer

import (
	"encoding/json"
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
	EventProcessHandler

	Producer     producer.ScanProducer
	QueryHandler query.ConventionalDNSQueryHandlerI
}

func (ddr *DDRProcessEventHandler) ScheduleScans(ddrScan *scan.DDRScan) {
	// schedule DoE scans
	if ddrScan.Meta.ScheduleDoEScans {
		logrus.Infof("schedule DoE and certificate scans for DDR scan %s", ddrScan.Meta.ScanId)

		if ddrScan.Result != nil &&
			ddrScan.Result.Response != nil &&
			ddrScan.Result.Response.ResponseMsg != nil &&
			len(ddrScan.Result.Response.ResponseMsg.Answer) > 0 {
			// let's produce the scans
			logrus.Debugf("got %d SVCB answers, schedule DoE scans", len(ddrScan.Result.Response.ResponseMsg.Answer))
			// parse DDR response
			scans, errColl := ddrScan.CreateScansFromResponse()
			ddrScan.Meta.AddError(errColl...)

			// schedule
			for _, s := range scans {
				if err := ddr.Producer.Produce(s, GetKafkaTopicFromScan(s)); err != nil {
					logrus.Errorf("failed to produce scan of type %s: %v", s.GetType(), err)
					ddrScan.Meta.AddError(
						custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true),
					)
				}
			}
		} else {
			logrus.Infof("no DoE scans to schedule since there was no SVCB answers %s", ddrScan.Meta.ScanId)
		}
	}

	// schedule PTR scan
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
		// getting error on invalid ip is not possible at this point
		_ = q.SetQueryMsg(ip.String())

		q.QueryMsg.RecursionDesired = true
		q.Host = query.DEFAULT_RECURSIVE_RESOLVER

		ptrScan := scan.NewPTRScan(&q.ConventionalDNSQuery, ddrScan.Meta.ScanId, ddrScan.Meta.RootScanId, ddrScan.Meta.RunId, ddrScan.Meta.VantagePoint)

		// produce PTR scan
		if err := ddr.Producer.Produce(ptrScan, GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, ddrScan.Meta.VantagePoint)); err != nil {
			logrus.Errorf("failed to produce PTR scan: %v", err)
			ddrScan.Meta.AddError(
				custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true),
			)
		}
	}

	// let's flush the producer
	ddr.Producer.Flush(1000)
}

func (ddr *DDRProcessEventHandler) Process(msg *kafka.Message, storage storage.StorageHandler) error {
	ddrScan := &scan.DDRScan{}
	err := json.Unmarshal(msg.Value, ddrScan)
	if err != nil {
		logrus.Errorf("error unmarshaling DDR scan: %s", err.Error())
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
		// produce PTR and DoE scans
		ddr.ScheduleScans(ddrScan)
	}

	err = storage.Store(ddrScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", ddrScan.Meta.ScanId, err.Error())
	}

	return err
}

func NewKafkaDDREventConsumer(
	config *KafkaConsumerConfig,
	prod producer.ScanProducer,
	storageHandler storage.StorageHandler,
	queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {
	if config != nil && config.ConsumerGroup == "" {
		config.ConsumerGroup = DEFAULT_DDR_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &DDRProcessEventHandler{
			Producer:     prod,
			QueryHandler: query.NewDDRQueryHandler(queryConfig),
		}, nil
	}

	kec, err = NewKafkaEventConsumer(config, newPh, storageHandler)

	return
}
