package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestFingerprintScan_RealWorld(t *testing.T) {
	t.Parallel()

	t.Run("version.bind", func(t *testing.T) {
		t.Parallel()

		s := scan.NewFingerprintScan("8.8.8.8", "parent", "root", "run", "vantagepoint")

		qh := query.NewConventionalDNSQueryHandler(nil)

		res, err := qh.Query(s.VersionBindQuery)
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("version.server", func(t *testing.T) {
		t.Parallel()

		s := scan.NewFingerprintScan("8.8.8.8", "parent", "root", "run", "vantagepoint")

		qh := query.NewConventionalDNSQueryHandler(nil)

		res, err := qh.Query(s.VersionServerQuery)
		assert.NoError(t, err)
		assert.NotNil(t, res)
	})

	t.Run("ssh", func(t *testing.T) {
		t.Parallel()

		s := scan.NewFingerprintScan("github.com", "parent", "root", "run", "vantagepoint")

		qh := query.NewSSHQueryHandler(nil)

		res, err := qh.Query(s.SSHQuery)

		assert.NoError(t, err)
		assert.NotNil(t, res)

		assert.NotNil(t, res.PubKeyFingerprint)
		assert.NotNil(t, res.PubKeyType)
	})
}

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
