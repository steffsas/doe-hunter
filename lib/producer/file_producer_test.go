package producer_test

import (
	"os"
	"testing"

	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestFileProducer_Produce(t *testing.T) {
	t.Parallel()

	host := "8.8.8.8"
	topic := "test-topic"
	vp := "test-vp"

	t.Run("test valid produce on single file", func(t *testing.T) {
		t.Parallel()

		tmp, err := os.MkdirTemp("", "tests-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tmp)

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

		fp := &producer.FileProducer{
			NewScan:  newScan,
			Producer: mkp,
		}

		err = fp.Produce(f.Name(), topic, vp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, topic)
		calls := mkp.Calls

		produceCounter := 0
		for _, call := range calls {
			if call.Method == "Produce" {
				produceCounter++

				args := call.Arguments

				s := args.Get(0).(scan.Scan)

				ddrScan, ok := s.(*scan.DDRScan)
				require.True(t, ok)

				require.Equal(t, topic, args[1])
				require.Equal(t, vp, ddrScan.Meta.VantagePoint)
				require.Equal(t, host, ddrScan.Query.Host)
			}
		}

		require.Equal(t, 2, produceCounter)
	})
}
