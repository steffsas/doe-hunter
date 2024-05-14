package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDDRScan(t *testing.T) {
	// setup
	host := "test"
	port := 1234
	scheduleDoEScans := true

	query := query.NewDDRQuery()
	query.Host = host
	query.Port = port

	// create scan
	ddrScan := scan.NewDDRScan(query, scheduleDoEScans)

	require.NotNil(t, ddrScan)
	require.NotNil(t, ddrScan.Meta)
	assert.NotEmpty(t, ddrScan.Meta.ScanId)
	assert.Equal(t, host, ddrScan.Query.Host)
	assert.Equal(t, port, ddrScan.Query.Port)
	assert.Equal(t, scheduleDoEScans, ddrScan.Meta.ScheduleDoEScans)
	assert.Equal(t, 0, len(ddrScan.Meta.Errors))
}
