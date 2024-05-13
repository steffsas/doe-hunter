package storage

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
)

type EmptyStorageHandler struct {
	StorageHandler
}

func (esh *EmptyStorageHandler) Open() (err error) {
	return nil
}

func (esh *EmptyStorageHandler) Close() (err error) {
	return nil
}

func (esh *EmptyStorageHandler) Store(data interface{}) (err error) {
	logrus.Warn("empty storage handler does not store anything")
	bytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	logrus.Info(string(bytes))
	return nil
}
