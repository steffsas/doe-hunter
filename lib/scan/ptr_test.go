package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestPTRScan_Constructor(t *testing.T) {
	t.Parallel()
	t.Run("nil query", func(t *testing.T) {
		t.Parallel()
		scan := scan.NewPTRScan(nil, "parent", "root", "run", "vantagepoint")

		// test
		assert.Equal(t, "PTR", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, "parent", scan.GetMetaInformation().ParentScanId, "should have returned parent")
		assert.Equal(t, "root", scan.GetMetaInformation().RootScanId, "should have returned root")
		assert.Equal(t, "run", scan.GetMetaInformation().RunId, "should have returned run")
		assert.Equal(t, "vantagepoint", scan.GetMetaInformation().VantagePoint, "should have returned vantagepoint")
	})

	t.Run("non-nil query", func(t *testing.T) {
		t.Parallel()
		q := query.NewConventionalQuery()
		scan := scan.NewPTRScan(q, "parent", "root", "run", "vantagepoint")

		// test
		assert.Equal(t, "PTR", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, q, scan.Query, "should have attached query")
		assert.Equal(t, "parent", scan.GetMetaInformation().ParentScanId, "should have returned parent")
		assert.Equal(t, "root", scan.GetMetaInformation().RootScanId, "should have returned root")
		assert.Equal(t, "run", scan.GetMetaInformation().RunId, "should have returned run")
		assert.Equal(t, "vantagepoint", scan.GetMetaInformation().VantagePoint, "should have returned vantagepoint")
	})
}

func TestPTRScan_Marshall(t *testing.T) {
	t.Parallel()
	scan := scan.NewPTRScan(nil, "parent", "root", "run", "vantagepoint")
	bytes, err := scan.Marshal()

	// test
	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, bytes, "should have returned bytes")
}
