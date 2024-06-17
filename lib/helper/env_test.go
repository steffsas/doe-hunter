package helper_test

import (
	"os"
	"testing"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadEnv(t *testing.T) {
	t.Run("valid load env", func(t *testing.T) {
		tmp, err := os.MkdirTemp("", "tests-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmp)

		f, err := os.CreateTemp(tmp, "test-*.env")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer f.Close()

		_, err = f.WriteString("RUN=consumer")
		if err != nil {
			t.Fatalf("failed to write to file: %v", err)
		}

		err = helper.LoadEnv(f.Name())
		require.NoError(t, err)

		run, ok := os.LookupEnv("RUN")
		require.True(t, ok)
		assert.Equal(t, "consumer", run)
	})

	t.Run("error load env", func(t *testing.T) {
		err := helper.LoadEnv("nonexistent")
		assert.Error(t, err)
	})
}

func TestGetEnvVar(t *testing.T) {
	t.Run("valid get env var", func(t *testing.T) {
		t.Setenv("RUN", "consumer")

		value, err := helper.GetEnvVar("RUN", true)
		require.NoError(t, err)
		assert.Equal(t, "consumer", value)
	})

	t.Run("error get env var", func(t *testing.T) {
		value, err := helper.GetEnvVar("SOMEENVVAR", true)
		assert.Error(t, err)
		assert.Empty(t, value)
	})

	t.Run("invalid run env", func(t *testing.T) {
		t.Setenv(helper.RUN_ENV, "invalid_run_type")

		value, err := helper.GetEnvVar(helper.RUN_ENV, true)
		assert.Error(t, err)
		assert.Empty(t, value)
	})

	t.Run("invalid protocol env var", func(t *testing.T) {
		t.Setenv(helper.PROTOCOL_ENV, "invalid_protocol_type")

		value, err := helper.GetEnvVar(helper.PROTOCOL_ENV, true)
		assert.Error(t, err)
		assert.Empty(t, value)
	})
}

func TestGetThreads(t *testing.T) {
	os.Unsetenv(helper.THREADS_ENV)
	os.Unsetenv(helper.THREADS_DOH_ENV)

	t.Run("valid get threads", func(t *testing.T) {
		t.Setenv(helper.THREADS_DOH_ENV, "5")

		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		require.NoError(t, err)
		assert.Equal(t, 5, threads)
	})

	t.Run("consider precedence", func(t *testing.T) {
		t.Setenv(helper.THREADS_ENV, "10")
		t.Setenv(helper.THREADS_DOH_ENV, "5")

		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		require.NoError(t, err)
		assert.Equal(t, 5, threads)
	})

	t.Run("return threads if specific one is not set", func(t *testing.T) {
		t.Setenv(helper.THREADS_ENV, "10")

		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		require.NoError(t, err)
		assert.Equal(t, 10, threads)
	})

	t.Run("threads not set", func(t *testing.T) {
		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		assert.Error(t, err)
		assert.Zero(t, threads)
	})

	t.Run("invalid threads not set", func(t *testing.T) {
		t.Setenv(helper.THREADS_ENV, "somethreads")

		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		assert.Error(t, err)
		assert.Zero(t, threads)
	})

	t.Run("invalid specific threads not set", func(t *testing.T) {
		t.Setenv(helper.THREADS_DOH_ENV, "somethreads")

		threads, err := helper.GetThreads(helper.THREADS_DOH_ENV)
		assert.Error(t, err)
		assert.Zero(t, threads)
	})
}
