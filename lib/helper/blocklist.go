package helper

import (
	"bufio"
	"net"
	"os"

	"github.com/sirupsen/logrus"
)

const DEFAULT_BLOCKLIST_PATH = "blocklist.conf"

// nolint: gochecknoglobals
var BlockedIPs = Blocklist{}

type Blocklist struct {
	list []net.IPNet
}

func (b *Blocklist) Load(filePath string) error {
	// load blocklist from file
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		// check whether the line is ip/cidr
		if _, ipnet, err := net.ParseCIDR(scanner.Text()); err == nil {
			b.list = append(b.list, *ipnet)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (b *Blocklist) Contains(ip net.IP) bool {
	for _, ipnet := range b.list {
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

func InitBlocklist() error {
	if path, err := GetEnvVar(BLOCKLIST_FILE_PATH_ENV, true); err == nil {
		return BlockedIPs.Load(path)
	} else {
		logrus.Debugf("No blocklist file path provided, using default path %s", DEFAULT_BLOCKLIST_PATH)
		return BlockedIPs.Load(DEFAULT_BLOCKLIST_PATH)
	}
}
