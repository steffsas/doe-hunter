package query

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/steffsas/doe-hunter/lib/custom_errors"
	"golang.org/x/crypto/ssh"
)

const SSH_PORT = 22
const SSH_TIMEOUT = 2500 * time.Millisecond

type SSHQuery struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Timeout  time.Duration
	Username string `json:"username"`
}

type SSHResponse struct {
	SSHEnabled        bool                      `json:"ssh_enabled"`
	PubKeyType        string                    `json:"pub_key_type"`
	PubKeyFingerprint string                    `json:"pub_key_fingerprint"`
	OpenSSHServer     bool                      `json:"openssh_server"`
	Errors            []custom_errors.DoEErrors `json:"errors"`
}

type SSHDialWrapper struct{}

func (sc *SSHDialWrapper) NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	return ssh.NewClientConn(c, addr, config)
}

type TCPDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type SSHDialer interface {
	NewClientConn(c net.Conn, addr string, config *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error)
}

type SSHQueryHandler struct {
	TCPDialer TCPDialer
	SSHDialer SSHDialer
}

func (qh *SSHQueryHandler) Query(query *SSHQuery) (*SSHResponse, custom_errors.DoEErrors) {
	res := &SSHResponse{}
	res.SSHEnabled = false
	res.OpenSSHServer = false

	if query == nil {
		err := custom_errors.NewQueryConfigError(custom_errors.ErrQueryNil, true)
		res.Errors = append(res.Errors, err)
		return res, err
	}

	// let's first try to connect to the SSH server
	con, err := qh.TCPDialer.Dial("tcp", fmt.Sprintf("%s:%d", query.Host, query.Port))
	if err != nil {
		dialErr := custom_errors.NewQueryError(custom_errors.ErrQueryDial, false)
		dialErr.AddInfo(err)
		res.Errors = append(res.Errors, dialErr)
		return res, dialErr
	}

	config := &ssh.ClientConfig{
		// this function is called to check whether the pubkey is considered to be valid
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			res.PubKeyFingerprint = base64.StdEncoding.EncodeToString([]byte(key.Marshal()))
			res.PubKeyType = key.Type()

			res.SSHEnabled = true
			return nil
		},
		Timeout: query.Timeout,
	}

	sshCon, _, _, err := qh.SSHDialer.NewClientConn(con, fmt.Sprintf("%s:%d", query.Host, query.Port), config)

	if err != nil {
		dialErr := custom_errors.NewQueryError(custom_errors.ErrQueryDial, false)
		dialErr.AddInfo(err)
		res.Errors = append(res.Errors, dialErr)
		// return no error since it will fail anyways
		return res, nil
	} else {
		// got a connection without auth!
		res.OpenSSHServer = true
		if sshCon != nil {
			sshCon.Close()
		}
	}

	return res, nil
}

func NewSSHQuery(host string) *SSHQuery {
	return &SSHQuery{
		Host:    host,
		Port:    SSH_PORT,
		Timeout: SSH_TIMEOUT,
	}
}

func NewSSHQueryHandler(config *QueryConfig) *SSHQueryHandler {
	qh := &SSHQueryHandler{}

	dialer := &net.Dialer{
		Timeout: SSH_TIMEOUT,
	}

	if config != nil {
		dialer.LocalAddr = &net.TCPAddr{
			IP:   config.LocalAddr,
			Port: 0,
		}
	}

	qh.TCPDialer = dialer
	qh.SSHDialer = &SSHDialWrapper{}

	return qh
}
