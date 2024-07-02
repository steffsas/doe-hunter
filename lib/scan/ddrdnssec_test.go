package scan_test

import (
	"encoding/json"
	"testing"

	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDDRDNSSEC_New(t *testing.T) {
	t.Parallel()
	t.Run("valid new DNSSEC scan", func(t *testing.T) {
		t.Parallel()
		scan := scan.NewDDRDNSSECScan("target", "host", "parent", "root", "run", "vantagepoint")

		assert.NotNil(t, scan.Meta)
		require.NotNil(t, scan.Query)
		assert.Equal(t, scan.Query.Host, "host")
	})
}

func TestDDRDNSSEC_Marshall(t *testing.T) {
	t.Parallel()
	s := scan.NewDDRDNSSECScan("target", "host", "parent", "root", "run", "vantagepoint")
	bytes, err := s.Marshall()

	// test
	assert.Nil(t, err, "should not have returned an error")
	assert.NotNil(t, bytes, "should have returned bytes")

	// unmarshall again
	scan2 := &scan.DDRDNSSECScan{}
	err = json.Unmarshal(bytes, scan2)
	assert.Nil(t, err, "should not have returned an error")
	assert.Equal(t, s.GetIdentifier(), scan2.GetIdentifier())
	assert.Equal(t, s.GetScanId(), scan2.GetScanId())
	assert.Equal(t, s.GetType(), scan2.GetType())
	assert.Equal(t, s.GetMetaInformation().Errors, scan2.GetMetaInformation().Errors)
}
