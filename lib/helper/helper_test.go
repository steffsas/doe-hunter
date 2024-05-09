package helper_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/stretchr/testify/assert"
)

func TestGetFullHostFromHostPort(t *testing.T) {
	host := "localhost"
	port := 8080
	expected := "localhost:8080"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}
