package custom_errors_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"github.com/stretchr/testify/assert"
)

func TestCustomErrors_Constructors(t *testing.T) {
	t.Parallel()

	err := errors.New("test")

	t.Run("new generic error", func(t *testing.T) {
		t.Parallel()
		// setup
		ge := custom_errors.NewGenericError(err, true)

		// test
		assert.NotNil(t, ge, "should not be nil")
		assert.Equal(t, ge.GetErrorId(), custom_errors.GENERIC_ERROR)
	})

	t.Run("new certificate error", func(t *testing.T) {
		t.Parallel()
		// setup
		ce := custom_errors.NewCertificateError(err, true)

		// test
		assert.NotNil(t, ce, "should not be nil")
		assert.Equal(t, ce.GetErrorId(), custom_errors.CERTIFICATE_ERROR)
	})

	t.Run("new unknown error", func(t *testing.T) {
		t.Parallel()
		// setup
		ue := custom_errors.NewUnknownError(err, true)

		// test
		assert.NotNil(t, ue, "should not be nil")
		assert.Equal(t, ue.GetErrorId(), custom_errors.UNKNOWN_ERROR)
	})

	t.Run("new query error", func(t *testing.T) {
		t.Parallel()
		// setup
		qe := custom_errors.NewQueryError(err, true)

		// test
		assert.NotNil(t, qe, "should not be nil")
		assert.Equal(t, qe.GetErrorId(), custom_errors.QUERY_ERROR)
	})

	t.Run("new query config error", func(t *testing.T) {
		t.Parallel()
		// setup
		qce := custom_errors.NewQueryConfigError(err, true)

		// test
		assert.NotNil(t, qce, "should not be nil")
		assert.Equal(t, qce.GetErrorId(), custom_errors.QUERY_CONFIG_ERROR)
	})
}

func TestCustomErrors_ContainsCriticalError(t *testing.T) {
	t.Parallel()

	t.Run("contains critical error", func(t *testing.T) {
		t.Parallel()
		// setup
		errColl := []custom_errors.DoEErrors{
			custom_errors.NewGenericError(errors.New("test"), true),
			custom_errors.NewQueryError(errors.New("test"), true),
		}

		critical := custom_errors.ContainsCriticalErr(errColl)

		fmt.Println(critical)

		// test
		assert.True(t, critical, "should return true")
	})

	t.Run("does not contain critical error", func(t *testing.T) {
		t.Parallel()
		// setup
		errColl := []custom_errors.DoEErrors{
			custom_errors.NewGenericError(errors.New("test"), false),
			custom_errors.NewQueryError(errors.New("test"), false),
		}

		// test
		assert.False(t, custom_errors.ContainsCriticalErr(errColl), "should return false")
	})
}

func TestCustomErrors_DoEError(t *testing.T) {
	t.Parallel()

	t.Run("get error id", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)

		// test
		assert.Equal(t, ce.GetErrorId(), custom_errors.GENERIC_ERROR)
	})

	t.Run("is certificate error", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewCertificateError(err, true)

		// test
		assert.True(t, ce.IsCertificateError())
	})

	t.Run("additional info", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)
		ce.AddInfoString("additional info")

		// test
		assert.Equal(t, "additional info", ce.AdditionalInfo)
	})

	t.Run("additional info twice", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)
		ce.AddInfoString("additional info")
		ce.AddInfoString("additional info")

		// test
		assert.Equal(t, "additional info, additional info", ce.AdditionalInfo)
	})

	t.Run("add info on error obj", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)
		ce.AddInfo(errors.New("additional info"))

		// test
		assert.Equal(t, "additional info", ce.AdditionalInfo)
	})

	t.Run("add info on custom error error obj", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)
		ce.AddInfo(custom_errors.NewGenericError(errors.New("some info"), true))

		// test
		assert.Equal(t, "scan_error in testing.tRunner: some info", ce.AdditionalInfo)
	})

	t.Run("check for error type", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)

		// test
		assert.True(t, ce.IsError(custom_errors.GENERIC_ERROR))
	})

	t.Run("empty error to addinfo", func(t *testing.T) {
		t.Parallel()

		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)
		ce.AddInfo(nil)

		// test
		assert.Equal(t, "", ce.AdditionalInfo)
	})

	t.Run("error output with additional info", func(t *testing.T) {
		t.Parallel()
		// setup
		err := errors.New("test")
		ce := custom_errors.NewGenericError(err, true)
		ce.AddInfoString("additional info")

		// test
		assert.Equal(t, "scan_error in testing.tRunner: test - additional info: additional info", ce.Error())
	})
}
