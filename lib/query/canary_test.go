package query_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/require"
)

func TestCanaryQuery_RealWorld(t *testing.T) {
	t.Parallel()

	q := query.NewCanaryQuery(scan.CANARY_MOZILLA_DOMAIN, "1.1.1.1")
	qh := query.NewCanaryQueryHandler(nil)

	res, err := qh.Query(q)
	require.Nil(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Response.ResponseMsg)
}
