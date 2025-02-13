package producer_test

import (
	"os"
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestFileProducer_Produce(t *testing.T) {
	t.Parallel()

	host := "8.8.8.8"
	vp := "test-vp"
	ipVersion := "ipv4"

	newScans := producer.GetProducibleScansFactory(vp, ipVersion)

	t.Run("test valid produce on single file", func(t *testing.T) {
		t.Parallel()

		tmp := t.TempDir()

		f, err := os.CreateTemp(tmp, "test-*.csv")
		if err != nil {
			return
		}
		defer f.Close()

		_, err = f.WriteString(host + "\n")
		require.NoError(t, err)
		_, err = f.WriteString(host)
		require.NoError(t, err)

		mkp := &mockedScanProducer{}
		mkp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mkp.On("Flush", mock.Anything).Return(0)
		mkp.On("Close", mock.Anything).Return(nil)
		mkp.On("WatchEvents").Return()

		fp := &producer.FileProducer{
			GetProducibleScans: newScans,
			Producer:           mkp,
		}

		err = fp.Produce(f.Name())

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp))
		// mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp))
		calls := mkp.Calls

		produceCounter := 0
		ddrScanChecked := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments

				s := args.Get(0).(scan.Scan)

				if ddrScan, ok := s.(*scan.DDRScan); ok {
					produceCounter++

					require.True(t, ok)

					require.Equal(t, vp, ddrScan.Meta.VantagePoint)
					require.Equal(t, host, ddrScan.Query.Host)

					ddrScanChecked = true
				}
			}
		}

		require.Equal(t, 2, produceCounter)
		require.True(t, ddrScanChecked)
	})
}
