package consumer

import (
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func RedoDoEScanOnCertError(err custom_errors.DoEErrors, oldScan scan.DoEScan, newScan scan.DoEScan, producer producer.ScanProducer) {
	if err != nil {
		if err.IsCertificateError() {
			newScan.GetDoEQuery().SkipCertificateVerify = true

			err := producer.Produce(newScan, GetKafkaTopicFromScan(newScan))
			if err != nil {
				logrus.Errorf("error rescheduling DoE scan %s: %s", newScan.GetMetaInformation().ScanId, err)
				genericErr := custom_errors.NewGenericError(err, true)
				oldScan.GetMetaInformation().AddError(genericErr)
			} else {
				producer.Flush(1000)
			}
		}
	}
}

func GetKafkaVPTopic(topic string, vantagePoint string) string {
	return topic + "-" + vantagePoint
}

func GetKafkaTopicFromScan(s scan.Scan) string {
	switch s.GetType() {
	case scan.DOH_SCAN_TYPE:
		return GetKafkaVPTopic(k.DEFAULT_DOH_TOPIC, s.GetMetaInformation().VantagePoint)
	case scan.DOQ_SCAN_TYPE:
		return GetKafkaVPTopic(k.DEFAULT_DOQ_TOPIC, s.GetMetaInformation().VantagePoint)
	case scan.DOT_SCAN_TYPE:
		return GetKafkaVPTopic(k.DEFAULT_DOT_TOPIC, s.GetMetaInformation().VantagePoint)
	case scan.CERTIFICATE_SCAN_TYPE:
		return GetKafkaVPTopic(k.DEFAULT_CERTIFICATE_TOPIC, s.GetMetaInformation().VantagePoint)
	default:
		return ""
	}
}
