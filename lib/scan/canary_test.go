package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestCanaryScan_Constructor(t *testing.T) {
	t.Parallel()
	t.Run("nil query", func(t *testing.T) {
		t.Parallel()
		scan := scan.NewCanaryScan(nil, "runId", "vantagePoint")

		// test
		assert.Equal(t, "canary", scan.GetType(), "should have returned canary")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, "runId", scan.GetMetaInformation().RunId, "should have returned runId")
		assert.Equal(t, "vantagePoint", scan.GetMetaInformation().VantagePoint, "should have returned vantagePoint")
	})

	t.Run("non-nil query", func(t *testing.T) {
		t.Parallel()

		host := "1.1.1.1"
		canaryDomain := "canaryDomain"

		q := query.NewCanaryQuery(canaryDomain, host)
		scan := scan.NewCanaryScan(q, "runId", "vantagePoint")

		// test
		assert.NotEmpty(t, scan.GetScanId(), "should have returned identifier")
		assert.Contains(t, scan.GetIdentifier(), "canary|canaryDomain|1.1.1.1|53", "should have returned identifier")
		assert.Equal(t, "canary", scan.GetType(), "should have returned canary")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, q, scan.Query, "should have attached query")
		assert.Equal(t, "canaryDomain", scan.Query.QueryMsg.Question[0].Name, "should have attached canary query")
		assert.Equal(t, "runId", scan.GetMetaInformation().RunId, "should have returned runId")
		assert.Equal(t, "vantagePoint", scan.GetMetaInformation().VantagePoint, "should have returned vantagePoint")
	})
}

func TestCanaryScan_Marshall(t *testing.T) {
	t.Parallel()
	scan := scan.NewCanaryScan(nil, "runId", "vantagePoint")
	bytes, err := scan.Marshall()

	// test
	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, bytes, "should have returned bytes")
}
