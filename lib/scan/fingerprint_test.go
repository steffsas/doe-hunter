package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestFingerprintScan_New(t *testing.T) {
	t.Parallel()
	s := scan.NewFingerprintScan("host", "parent", "root", "run", "vantagepoint")

	// test
	assert.Equal(t, scan.FINGERPRINT_SCAN_TYPE, s.GetType(), "should have returned Fingerprint")
	assert.NotNil(t, s.Meta, "meta should not be nil")
	assert.NotNil(t, s.VersionBindQuery, "query should not be nil")
	assert.NotNil(t, s.VersionServerQuery, "query should not be nil")
	assert.NotNil(t, s.SSHQuery, "query should not be nil")
	assert.Nil(t, s.VersionBindResult, "result should be nil")
	assert.Nil(t, s.VersionServerResult, "result should be nil")
	assert.Nil(t, s.SSHResult, "result should be nil")
}
