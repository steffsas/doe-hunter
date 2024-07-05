package helper_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/stretchr/testify/assert"
)

func TestBlocklist_Init(t *testing.T) {
	helper.BlockedIPs = helper.Blocklist{}

	t.Run("default blocklist", func(t *testing.T) {
		t.Setenv(helper.BLOCKLIST_FILE_PATH_ENV, "../../blocklist.conf")

		te, e := helper.GetEnvVar(helper.BLOCKLIST_FILE_PATH_ENV, true)
		fmt.Println(te, e)

		err := helper.InitBlocklist()

		// test
		assert.Nil(t, err, "should not have returned an error")
		assert.NotEmpty(t, helper.BlockedIPs, "should have returned a blocklist")

		helper.BlockedIPs = helper.Blocklist{}
	})

	t.Run("load default if env not set", func(t *testing.T) {
		t.Setenv(helper.BLOCKLIST_FILE_PATH_ENV, "")

		err := helper.InitBlocklist()

		// test
		assert.NotNil(t, err, "should not have returned an error")
		assert.Empty(t, helper.BlockedIPs, "should have returned a blocklist")

		helper.BlockedIPs = helper.Blocklist{}
	})
}

func TestBlocklist_Load(t *testing.T) {
	t.Parallel()

	t.Run("load blocklist", func(t *testing.T) {
		t.Parallel()

		b := helper.Blocklist{}
		err := b.Load("../../blocklist.conf")

		// test
		assert.Nil(t, err, "should not have returned an error")
		assert.NotEmpty(t, b, "should have returned a blocklist")
	})

	t.Run("load blocklist with invalid path", func(t *testing.T) {
		t.Parallel()
		b := helper.Blocklist{}
		err := b.Load("invalid.conf")

		// test
		assert.NotNil(t, err, "should have returned an error")
		assert.Empty(t, b, "should have returned an empty blocklist")
	})
}

func TestBlocklist_Contains(t *testing.T) {
	t.Parallel()

	b := helper.Blocklist{}
	b.Load("../../blocklist.conf")

	t.Run("google should not be blocked", func(t *testing.T) {
		t.Parallel()

		ip := "8.8.8.8"
		contains := b.Contains(net.ParseIP(ip))

		assert.False(t, contains, "google should not be blocked")
	})

	t.Run("google should not be blocked", func(t *testing.T) {
		t.Parallel()

		ip := "127.0.0.1"
		contains := b.Contains(net.ParseIP(ip))

		assert.True(t, contains, "localhost should be blocked")
	})
}
