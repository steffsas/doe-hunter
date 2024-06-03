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

	DoeProducer  DoEAndCertScanScheduler
	PTRProducer  PTRScanScheduler
	QueryHandler query.ConventionalDNSQueryHandlerI
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
		// produce DoE scans
		ddr.DoeProducer.ScheduleScans(ddrScan)

		// produce PTR scan
		ddr.PTRProducer.ScheduleScans(ddrScan)
	}

	err = storage.Store(ddrScan)
	if err != nil {
		logrus.Errorf("failed to store %s: %v", ddrScan.Meta.ScanId, err.Error())
	}

	return err
}

func NewKafkaDDREventConsumer(
	consumerConfig *KafkaConsumerConfig,
	producerConfig *producer.KafkaProducerConfig,
	storageHandler storage.StorageHandler,
	queryConfig *query.QueryConfig) (kec *KafkaEventConsumer, err error) {

	if consumerConfig != nil && consumerConfig.ConsumerGroup == "" {
		consumerConfig.ConsumerGroup = DEFAULT_DDR_CONSUMER_GROUP
	}

	newPh := func() (EventProcessHandler, error) {
		return &DDRProcessEventHandler{
			QueryHandler: query.NewDDRQueryHandler(queryConfig),
			DoeProducer: DoEAndCertScanScheduler{
				Producer: &ProduceFactory{
					Config: producerConfig,
				}},
			PTRProducer: PTRScanScheduler{
				Producer: &ProduceFactory{
					Config: producerConfig,
				}},
		}, nil
	}

	kec, err = NewKafkaEventConsumer(consumerConfig, newPh, storageHandler)

	return
}

type ProduceFactoryI interface {
	Produce(ddrScan *scan.DDRScan, newScan scan.Scan, topic string) error
}

type ProduceFactory struct {
	Config *producer.KafkaProducerConfig
}

func (p *ProduceFactory) Produce(ddrScan *scan.DDRScan, newScan scan.Scan, topic string) error {
	// TODO: this will create a socket on every call, should be optimized
	pr, err := producer.NewScanProducer(topic, p.Config)
	if err != nil {
		logrus.Errorf("failed to create scan producer: %v", err)
		ddrScan.Meta.AddError(custom_errors.NewGenericError(
			custom_errors.ErrProducerCreationFailed, true),
		)
		return err
	}
	defer pr.Close()

	err = pr.Produce(newScan)
	if err != nil {
		logrus.Errorf("failed to produce scan: %v", err)
		ddrScan.Meta.AddError(
			custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true),
		)
	}

	return err
}

type DoEAndCertScanScheduler struct {
	Producer ProduceFactoryI
}

func (dss *DoEAndCertScanScheduler) ScheduleScans(ddrScan *scan.DDRScan) {
	// schedule DoE scans
	if ddrScan.Meta.ScheduleDoEScans {
		logrus.Infof("schedule DoE and certificate scans for DDR scan %s", ddrScan.Meta.ScanId)

		if ddrScan.Result != nil &&
			ddrScan.Result.Response != nil &&
			ddrScan.Result.Response.ResponseMsg != nil &&
			len(ddrScan.Result.Response.ResponseMsg.Answer) > 0 {
			logrus.Debugf("got %d SVCB answers, schedule DoE scans", len(ddrScan.Result.Response.ResponseMsg.Answer))
			// parse DDR response
			scans, errColl := ddrScan.CreateScansFromResponse()
			ddrScan.Meta.AddError(errColl...)

			// schedule
			for _, s := range scans {
				switch s.GetType() {
				case scan.DOH_SCAN_TYPE:
					_ = dss.Producer.Produce(ddrScan, s, GetKafkaVPTopic(k.DEFAULT_DOH_TOPIC, ddrScan.Meta.VantagePoint))
				case scan.DOQ_SCAN_TYPE:
					_ = dss.Producer.Produce(ddrScan, s, GetKafkaVPTopic(k.DEFAULT_DOQ_TOPIC, ddrScan.Meta.VantagePoint))
				case scan.DOT_SCAN_TYPE:
					_ = dss.Producer.Produce(ddrScan, s, GetKafkaVPTopic(k.DEFAULT_DOT_TOPIC, ddrScan.Meta.VantagePoint))
				case scan.CERTIFICATE_SCAN_TYPE:
					_ = dss.Producer.Produce(ddrScan, s, GetKafkaVPTopic(k.DEFAULT_CERTIFICATE_TOPIC, ddrScan.Meta.VantagePoint))
				}
			}
		} else {
			logrus.Infof("no DoE scans to schedule since there was no SVCB answers %s", ddrScan.Meta.ScanId)
		}
	}
}

type PTRScanScheduler struct {
	Producer ProduceFactoryI
}

func (pss *PTRScanScheduler) ScheduleScans(ddrScan *scan.DDRScan) {
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

		ptrScan := scan.NewPTRScan(&q.ConventionalDNSQuery, ddrScan.Meta.ScanId, ddrScan.Meta.RootScanId, ddrScan.Meta.RunId)

		// produce PTR scan
		if err := pss.Producer.Produce(ddrScan, ptrScan, GetKafkaVPTopic(k.DEFAULT_PTR_TOPIC, ddrScan.Meta.VantagePoint)); err != nil {
			logrus.Errorf("failed to produce PTR scan: %v", err)
			ddrScan.Meta.AddError(
				custom_errors.NewGenericError(custom_errors.ErrProducerProduceFailed, true),
			)
		}
	}
}
