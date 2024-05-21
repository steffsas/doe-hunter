package consumer

import (
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
)

func RedoDoEScanOnCertError(err custom_errors.DoEErrors, oldScan scan.DoEScan, newScan scan.DoEScan, topic string) {
	if err != nil {
		if err.IsCertificateError() {
			newScan.GetDoEQuery().SkipCertificateVerify = true

			p, pErr := producer.NewScanProducer(topic, nil)
			if pErr != nil {
				genericErr := custom_errors.NewGenericError(pErr, true)
				logrus.Errorf("error creating DoH scan producer: %s", pErr)
				oldScan.GetMetaInformation().AddError(genericErr)
			}
			defer p.Close()

			pErr = p.Produce(newScan)
			if pErr != nil {
				logrus.Errorf("error rescheduling DoE scan %s: %s", newScan.GetMetaInformation().ScanId, err)
				genericErr := custom_errors.NewGenericError(pErr, true)
				oldScan.GetMetaInformation().AddError(genericErr)
			}
		}
	}
}
