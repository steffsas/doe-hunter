package storage_test

import (
	"testing"

	"github.com/steffsas/doe-hunter/lib/storage"
	"github.com/stretchr/testify/assert"
)

func TestEmptyStorageHandler_Open(t *testing.T) {
	disableLog()

	esh := &storage.EmptyStorageHandler{}
	err := esh.Open()
	assert.Nil(t, err)
}

func TestEmptyStorageHandler_Close(t *testing.T) {
	disableLog()

	esh := &storage.EmptyStorageHandler{}
	err := esh.Close()
	assert.Nil(t, err)
}

func TestEmptyStorageHandler_Store(t *testing.T) {
	disableLog()

	esh := &storage.EmptyStorageHandler{}
	err := esh.Store(nil)
	assert.Nil(t, err)
}
