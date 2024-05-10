package scan_test

import (
	"errors"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestScanMetaInformation(t *testing.T) {
	t.Parallel()
	t.Run("random scanid", func(t *testing.T) {
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.GenerateScanID()

		// test
		assert.NotEmpty(t, smi.ScanID)
	})

	t.Run("add error", func(t *testing.T) {
		// setup
		smi := &scan.ScanMetaInformation{}
		err := errors.New("test")
		smi.AddError(err)

		// test
		assert.Equal(t, 1, len(smi.Errors))
		assert.Equal(t, err, smi.Errors[0])
	})

	t.Run("set scheduled", func(t *testing.T) {
		time := time.Now()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.SetScheduled()

		// test
		assert.GreaterOrEqual(t, smi.Scheduled, time)
	})

	t.Run("set started", func(t *testing.T) {
		time := time.Now()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.SetStarted()

		// test
		assert.GreaterOrEqual(t, smi.Started, time)
	})

	t.Run("set finished", func(t *testing.T) {
		time := time.Now()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.SetFinished()

		// test
		assert.GreaterOrEqual(t, smi.Finished, time)
	})
}
