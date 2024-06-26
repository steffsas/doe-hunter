package query_test

import (
	"errors"
	"net"
	"testing"

	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type mockedTCPDialer struct {
	mock.Mock
}

func (m *mockedTCPDialer) Dial(network, address string) (conn net.Conn, err error) {
	args := m.Called(network, address)
	return args.Get(0).(net.Conn), args.Error(1)
}

type mockedSSHDialer struct {
	mock.Mock
}

func (m *mockedSSHDialer) NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (conn ssh.Conn, newChan <-chan ssh.NewChannel, reqChan <-chan *ssh.Request, err error) {
	args := m.Called(c, addr, config)
	if args.Get(0) == nil {
		return nil, args.Get(1).(<-chan ssh.NewChannel), args.Get(2).(<-chan *ssh.Request), args.Error(3)
	}

	return args.Get(0).(ssh.Conn), args.Get(1).(<-chan ssh.NewChannel), args.Get(2).(<-chan *ssh.Request), args.Error(3)
}

type mockedSSHConWrapper struct {
	mock.Mock
}

func (m *mockedSSHConWrapper) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestSSHQueryHandler_Query(t *testing.T) {
	t.Parallel()

	t.Run("real world", func(t *testing.T) {
		t.Parallel()

		q := query.NewSSHQuery("ns1.raiun.de")

		qh := query.NewSSHQueryHandler(nil)

		res, err := qh.Query(q)

		assert.NoError(t, err)
		require.NotNil(t, res)
		assert.True(t, res.SSHEnabled)
		assert.NotEmpty(t, res.PubKeyType)
		assert.NotEmpty(t, res.PubKeyFingerprint)
	})

	t.Run("nil query", func(t *testing.T) {
		qh := query.NewSSHQueryHandler(nil)

		res, err := qh.Query(nil)

		assert.NotNil(t, res)
		assert.Error(t, err)
	})

	t.Run("dial error", func(t *testing.T) {
		t.Parallel()

		err := errors.New("dial error")

		mtd := &mockedTCPDialer{}
		mtd.On("Dial", mock.Anything, mock.Anything).Return(
			&net.IPConn{},
			err,
		)

		q := query.NewSSHQuery("ns1.raiun.de")

		qh := query.NewSSHQueryHandler(nil)
		qh.TCPDialer = mtd

		res, qErr := qh.Query(q)

		assert.NotNil(t, res)
		assert.Error(t, qErr)
		assert.Contains(t, qErr.Error(), err.Error())
	})

	t.Run("successfull ssh dial", func(t *testing.T) {
		t.Parallel()

		mtd := &mockedTCPDialer{}
		mtd.On("Dial", mock.Anything, mock.Anything).Return(
			&net.IPConn{},
			nil,
		)

		msc := &mockedSSHConWrapper{}
		msc.On("Close").Return(nil)

		var chann <-chan ssh.NewChannel
		var reqChan <-chan *ssh.Request

		msd := &mockedSSHDialer{}
		msd.On("NewClientConn", mock.Anything, mock.Anything, mock.Anything).Return(
			nil,
			chann,
			reqChan,
			nil,
		)

		q := query.NewSSHQuery("ns1.raiun.de")

		qh := query.NewSSHQueryHandler(nil)
		qh.TCPDialer = mtd
		qh.SSHDialer = msd

		res, qErr := qh.Query(q)

		assert.NotNil(t, res)
		assert.NoError(t, qErr)
		assert.True(t, res.OpenSSHServer)
	})
}

func TestNewSSHQueryHandler(t *testing.T) {
	t.Parallel()

	config := &query.QueryConfig{
		LocalAddr: net.IPv4(127, 0, 0, 1),
	}

	qh := query.NewSSHQueryHandler(config)

	assert.NotNil(t, qh)
	assert.NotNil(t, qh.TCPDialer)
	assert.NotNil(t, qh.SSHDialer)
}
