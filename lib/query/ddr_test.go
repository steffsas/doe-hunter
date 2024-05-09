package query_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDDRQuery(t *testing.T) {
	//p := &DDRParser{}

	q := query.NewDDRQuery("8.8.8.8", 53)
	// TODO remove later on
	q.Protocol = "tcp"
	res, err := q.Query()

	assert.Nil(t, err, "should not have returned an error")
	require.NotNil(t, res, "should have returned a result")
	require.NotNil(t, res.ResponseMsg, "should have returned a DNS response")
	require.NotNil(t, res.ResponseMsg.Answer, "should have returned at least one DNS answer")

	for _, answer := range res.ResponseMsg.Answer {
		_, ok := answer.(*dns.SVCB)
		assert.True(t, ok, "should only have returned an SVCB record")
	}
}
