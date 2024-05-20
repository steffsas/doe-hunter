package scan_test

import (
	"errors"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestScanMetaInformation(t *testing.T) {
	t.Parallel()
	t.Run("random scanid", func(t *testing.T) {
		t.Parallel()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.GenerateScanId()

		// test
		assert.NotEmpty(t, smi.ScanId)
	})

	t.Run("add error", func(t *testing.T) {
		t.Parallel()
		// setup
		smi := &scan.ScanMetaInformation{}
		err := custom_errors.NewGenericError(errors.New("test"), true)
		smi.AddError(err)

		// test
		assert.Equal(t, 1, len(smi.Errors))
		assert.Equal(t, err, smi.Errors[0])
	})

	t.Run("set scheduled", func(t *testing.T) {
		t.Parallel()
		time := time.Now()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.SetScheduled()

		// test
		assert.GreaterOrEqual(t, smi.Scheduled, time)
	})

	t.Run("set started", func(t *testing.T) {
		t.Parallel()
		time := time.Now()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.SetStarted()

		// test
		assert.GreaterOrEqual(t, smi.Started, time)
	})

	t.Run("set finished", func(t *testing.T) {
		t.Parallel()
		time := time.Now()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.SetFinished()

		// test
		assert.GreaterOrEqual(t, smi.Finished, time)
	})

	t.Run("schedule", func(t *testing.T) {
		t.Parallel()
		// setup
		smi := &scan.ScanMetaInformation{}
		smi.Schedule()

		// test
		assert.NotEmpty(t, smi.ScanId)
		assert.GreaterOrEqual(t, smi.Scheduled, time.Time{})
	})
}
