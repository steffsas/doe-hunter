package scan_test

import (
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestScanRunCache_AddScan(t *testing.T) {
	t.Parallel()

	t.Run("should find an added scan", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		q.Host = "test-host"
		q.Port = 1234
		s := scan.NewDDRScan(q, true, "someRunId", "someVantagePoint")

		src := scan.NewScanRunContainer("test-run")
		src.AddScan(s)

		scanId, found := src.ContainsScan(s)

		assert.True(t, found, "scan should be found")
		assert.Equal(t, s.GetScanId(), scanId, "scan id should match")
	})
}

func TestScanRunCache_Timer(t *testing.T) {
	t.Parallel()

	t.Run("should return a timer", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		q.Host = "test-host"
		q.Port = 1234
		s := scan.NewDDRScan(q, true, "someRunId", "someVantagePoint")

		src := scan.NewScanRunContainer("test-run")
		src.CacheTime = 500 * time.Millisecond
		src.AddScan(s)

		time.Sleep(550 * time.Millisecond)

		_, found := src.ContainsScan(s)

		assert.False(t, found, "scan should not be found after timer expired and cleared the cache")
	})
}

func TestScanCache_AddScan(t *testing.T) {
	t.Parallel()

	t.Run("should find an added scan", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		q.Host = "test-host"
		q.Port = 1234
		s := scan.NewDDRScan(q, true, "someRunId", "someVantagePoint")

		src := scan.NewScanCache()
		src.AddScan(s)

		scanId, found := src.ContainsScan(s)

		assert.True(t, found, "scan should be found")
		assert.Equal(t, s.GetScanId(), scanId, "scan id should match")
	})

	t.Run("should not find a non-added scan", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		q.Host = "test-host"
		q.Port = 1234
		s := scan.NewDDRScan(q, true, "someRunId", "someVantagePoint")

		src := scan.NewScanCache()

		scanId, found := src.ContainsScan(s)

		assert.False(t, found, "scan should not be found")
		assert.Equal(t, "", scanId, "scan id should be empty")
	})
}

func TestScanCache_Clear(t *testing.T) {
	t.Parallel()

	t.Run("should clear the cache", func(t *testing.T) {
		t.Parallel()

		q := query.NewDDRQuery()
		q.Host = "test-host"
		q.Port = 1234
		s := scan.NewDDRScan(q, true, "someRunId", "someVantagePoint")

		src := scan.NewScanCache()
		src.AddScan(s)

		src.Clear()

		scanId, found := src.ContainsScan(s)

		assert.False(t, found, "scan should not be found after clearing the cache")
		assert.Equal(t, "", scanId, "scan id should be empty")
	})
}
