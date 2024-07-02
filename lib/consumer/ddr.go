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

// nolint: gochecknoglobals
var ScanCache = scan.NewScanCache()

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
			// let's parse the SVCB answers
			logrus.Debugf("got %d SVCB answers, schedule DoE scans", len(ddrScan.Result.Response.ResponseMsg.Answer))
			// parse DDR response
			scans, errColl := ddrScan.CreateScansFromResponse()
			ddrScan.Meta.AddError(errColl...)

			ddrChildren := []string{}
			for _, s := range scans {
				// use scan cache to only produce scans that haven't been produced yet
				if scanId, found := ScanCache.ContainsScan(s); found {
					logrus.Debugf("scan %s already in cache, not producing", scanId)
					ddrChildren = append(ddrChildren, scanId)
				} else {
					// got a new scan, add to cache and produce
					ddrChildren = append(ddrChildren, s.GetMetaInformation().ScanId)
					if err := ddr.Producer.Produce(s, GetKafkaTopicFromScan(s)); err != nil {
						logrus.Errorf("failed to produce scan of type %s: %v", s.GetType(), err)
						ddrScan.Meta.AddError(
							custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true).AddInfo(err),
						)
					} else {
						// add scan to cache
						ScanCache.AddScan(s)
					}
				}
			}
			ddrScan.Meta.Children = ddrChildren
		} else {
			logrus.Infof("no DoE scans to schedule since there was no SVCB answers %s", ddrScan.Meta.ScanId)
		}
	}

	// schedule fingerprint scan
	if ddrScan.Meta.ScheduleFingerprintScan {
		logrus.Infof("schedule fingerprint scan for DDR scan %s", ddrScan.Meta.ScanId)
		fingerprintScan := scan.NewFingerprintScan(ddrScan.Query.Host, ddrScan.Meta.RootScanId, ddrScan.Meta.ScanId, ddrScan.Meta.RunId, ddrScan.Meta.VantagePoint)
		if err := ddr.Producer.Produce(fingerprintScan, GetKafkaVPTopic(k.DEFAULT_FINGERPRINT_TOPIC, ddrScan.Meta.VantagePoint)); err != nil {
			logrus.Errorf("failed to produce fingerprint scan: %v", err)
			ddrScan.Meta.AddError(
				custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true).AddInfo(err),
			)
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
		// getting error on invalid ip is not possible at this point because we already parse the IP beforehand
		_ = q.SetQueryMsg(ip.String())

		ptrScan := scan.NewPTRScan(&q.ConventionalDNSQuery, ddrScan.Meta.ScanId, ddrScan.Meta.RootScanId, ddrScan.Meta.RunId, ddrScan.Meta.VantagePoint)

		// add to children
		ddrScan.Meta.Children = append(ddrScan.Meta.Children, ptrScan.Meta.ScanId)

		// produce PTR scan
		if err := ddr.Producer.Produce(ptrScan, GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, ddrScan.Meta.VantagePoint)); err != nil {
			logrus.Errorf("failed to produce PTR scan: %v", err)
			ddrScan.Meta.AddError(
				custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true).AddInfo(err),
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
