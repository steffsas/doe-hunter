package helper_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/stretchr/testify/assert"
)

func TestGetFullHostFromHostPort_Hostname(t *testing.T) {
	host := "localhost"
	port := 8080
	expected := "localhost:8080"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestGetFullHostFromPort_IPv4(t *testing.T) {
	host := "8.8.8.8"
	port := 53

	expected := "8.8.8.8:53"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestGetFullHostFromPort_IPv6(t *testing.T) {
	host := "2001:4860:4860::8888"
	port := 53

	expected := "[2001:4860:4860::8888]:53"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}

func TestGetFullHostFromPort_EmptyHost(t *testing.T) {
	host := ""
	port := 53

	expected := ":53"
	actual := helper.GetFullHostFromHostPort(host, port)

	assert.Equal(t, expected, actual)
}
