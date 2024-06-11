package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestCertificateScan_Constructor(t *testing.T) {
	t.Parallel()
	t.Run("nil query", func(t *testing.T) {
		t.Parallel()
		scan := scan.NewCertificateScan(nil, "parent", "root", "runid", "vantagepoint")

		// test
		assert.Equal(t, "certificate", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.NotEmpty(t, scan.GetScanId(), "should have returned a scan ID")
		assert.Equal(t, "parent", scan.GetMetaInformation().ParentScanId, "should have returned parent")
		assert.Equal(t, "root", scan.GetMetaInformation().RootScanId, "should have returned root")
		assert.Equal(t, "vantagepoint", scan.GetMetaInformation().VantagePoint, "should have returned vantagepoint")
	})

	t.Run("non-nil query", func(t *testing.T) {
		t.Parallel()
		q := query.NewCertificateQuery()
		scan := scan.NewCertificateScan(q, "parent", "root", "runid", "vantagepoint")

		// test
		assert.Equal(t, "certificate", scan.GetType(), "should have returned PTR")
		assert.NotNil(t, scan.Meta, "meta should not be nil")
		assert.NotNil(t, scan.Query, "query should not be nil")
		assert.Nil(t, scan.Result, "result should be nil")
		assert.Equal(t, q, scan.Query, "should have attached query")
		assert.NotEmpty(t, scan.GetScanId(), "should have returned a scan ID")
		assert.Equal(t, "parent", scan.GetMetaInformation().ParentScanId, "should have returned parent")
		assert.Equal(t, "root", scan.GetMetaInformation().RootScanId, "should have returned root")
		assert.Equal(t, "vantagepoint", scan.GetMetaInformation().VantagePoint, "should have returned vantagepoint")
	})
}

func TestCertificateScan_Marshall(t *testing.T) {
	t.Parallel()
	scan := scan.NewCertificateScan(nil, "parent", "root", "runid", "vantagepoint")
	bytes, err := scan.Marshall()

	// test
	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, bytes, "should have returned bytes")
}
