package consumer

import (
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	k "github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func RedoDoEScanOnCertError(err custom_errors.DoEErrors, oldScan scan.DoEScan, producer producer.ScanProducer) (newScanId string, scheduled bool) {
	if err != nil {
		if err.IsCertificateError() {
			metaInfo := oldScan.GetMetaInformation()
			newKafkaDoEScan := k.NewDoEKafkaScan(metaInfo.RunId, metaInfo.RootScanId, metaInfo.ParentScanId, oldScan.GetDoEQuery().Host, oldScan.GetMetaInformation().IsOnBlocklist, true)

			topic := GetKafkaTopicFromScan(oldScan)

			err := producer.Produce(newKafkaDoEScan, topic)
			if err != nil {
				logrus.Errorf("error rescheduling DoE scan %s on topic %s: %s", newKafkaDoEScan.Host, topic, err)
				genericErr := custom_errors.NewGenericError(err, true)
				oldScan.GetMetaInformation().AddError(genericErr)
			} else {
				producer.Flush(1000)
			}

			return newKafkaDoEScan.GetScanId(), true
		}
	}

	return "", false
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
	case scan.EDSR_SCAN_TYPE:
		return GetKafkaVPTopic(k.DEFAULT_EDSR_TOPIC, s.GetMetaInformation().VantagePoint)
	case scan.DDR_DNSSEC_SCAN_TYPE:
		return GetKafkaVPTopic(k.DEFAULT_DDR_DNSSEC_TOPIC, s.GetMetaInformation().VantagePoint)
	default:
		return ""
	}
}
