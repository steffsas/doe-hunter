package consumer_test

import (
	"fmt"
	"testing"

	"github.com/steffsas/doe-hunter/lib/consumer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestEDSR_StartEDSR(t *testing.T) {
	t.Parallel()

	t.Run("valid EDSR scan", func(t *testing.T) {
		t.Parallel()

		q := query.NewEDSRQuery("dns.google.")

		scan := &scan.EDSRScan{
			Meta: &scan.EDSRScanMetaInformation{
				ScanMetaInformation: *scan.NewScanMetaInformation("", "", "", ""),
			},
			Protocol:   "h2",
			TargetName: "dns.google.",
			Query:      q,
			Result:     &scan.EDSRResult{},
		}

		qh := query.NewEDSRQueryHandler(nil)

		pc := &consumer.EDSRProcessConsumer{
			QueryHandler: qh,
		}

		pc.StartEDSR(scan)

		fmt.Println(scan.Result.Redirections)

		assert.False(t, true)
	})
}
