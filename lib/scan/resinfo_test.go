package scan_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
)

func TestResinfo_NewResInfoScan(t *testing.T) {
	t.Parallel()

	t.Run("should return a new ResinfoScan", func(t *testing.T) {
		t.Parallel()

		targetName := "resolver.dns4all.eu."
		host := "resolver.dns4all.eu"

		s := scan.NewResInfoScan(targetName, host, "parent", "root", "run", "vantagepoint")

		assert.Equal(t, scan.RESINFO_SCAN_TYPE, s.GetType(), "should have returned Resinfo")
		assert.Equal(t, targetName, s.TargetName, "should have returned the correct target name")
		assert.Equal(t, host, s.Host, "should have returned the correct host")
	})
}
