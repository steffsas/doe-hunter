package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestDoHScan_Constructor(t *testing.T) {
	t.Parallel()
	t.Run("nil query", func(t *testing.T) {
		t.Parallel()
		scan := scan.NewDoHScan(nil, "parent", "root", "run")

		// test
		assert.Equal(t, "DoH", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, "parent", scan.GetMetaInformation().ParentScanId, "should have returned parent")
		assert.Equal(t, "root", scan.GetMetaInformation().RootScanId, "should have returned root")
		assert.Equal(t, "run", scan.GetMetaInformation().RunId, "should have returned run")
	})

	t.Run("non-nil query", func(t *testing.T) {
		t.Parallel()
		q := query.NewDoHQuery()
		scan := scan.NewDoHScan(q, "parent", "root", "run")

		// test
		assert.Equal(t, "DoH", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, q, scan.Query, "should have attached query")
		assert.Equal(t, "parent", scan.GetMetaInformation().ParentScanId, "should have returned parent")
		assert.Equal(t, "root", scan.GetMetaInformation().RootScanId, "should have returned root")
		assert.Equal(t, "run", scan.GetMetaInformation().RunId, "should have returned run")
	})
}

func TestDoHScan_Marshall(t *testing.T) {
	t.Parallel()
	scan := scan.NewDoHScan(nil, "parent", "root", "run")
	bytes, err := scan.Marshall()

	// test
	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, bytes, "should have returned bytes")
}

func TestDoHScan_DoEFunctions(t *testing.T) {
	t.Parallel()

	q := query.NewDoHQuery()
	scan := scan.NewDoHScan(q, "parent", "root", "run")

	// test
	assert.Equal(t, scan.GetScanId(), scan.GetMetaInformation().ScanId, "should have returned the same ID")
	assert.Equal(t, &q.DoEQuery, scan.GetDoEQuery(), "should have returned the same query")
}
