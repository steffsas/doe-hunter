package storage

import "github.com/sirupsen/logrus"

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
	logrus.Info("empty storage handler does not store anything")
	return nil
}
