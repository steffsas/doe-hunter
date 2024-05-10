package storage

type StorageHandler interface {
	Store(data interface{}) (err error)
	Open() (err error)
	Close() (err error)
}
