package storage_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MockedMongoCollection struct {
	mock.Mock
}

func (mmc *MockedMongoCollection) InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	args := mmc.Called(ctx, document, opts)
	return args.Get(0).(*mongo.InsertOneResult), args.Error(1)
}

type MockedMongoDatabase struct {
	mock.Mock
}

func (mmd *MockedMongoDatabase) Collection(name string) storage.MongoCollection {
	args := mmd.Called(name)

	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(storage.MongoCollection)
}

type MockedMongoClient struct {
	mock.Mock
}

func (mmc *MockedMongoClient) Database(name string, opts ...*options.DatabaseOptions) storage.MongoDatabase {
	args := mmc.Called(name)

	if args.Get(0) == nil {
		return nil
	}

	return args.Get(0).(storage.MongoDatabase)
}

func (mmc *MockedMongoClient) Disconnect(ctx context.Context) error {
	args := mmc.Called(ctx)
	return args.Error(0)
}

func GetMockedMongoClient() *MockedMongoClient {
	co := &MockedMongoCollection{}
	co.On("InsertOne", mock.Anything, mock.Anything, mock.Anything).Return(&mongo.InsertOneResult{}, nil)

	d := &MockedMongoDatabase{}
	d.On("Collection", mock.Anything).Return(co)

	c := &MockedMongoClient{}
	c.On("Database", mock.Anything).Return(d)
	c.On("Disconnect", mock.Anything).Return(nil)
	return c
}

// func TestMongoStorageHandler_RealWorld(t *testing.T) {
// 	// setup
// 	client, err := mongo.Connect(
// 		context.Background(),
// 		options.Client().ApplyURI("mongodb://root:example@localhost:27017"),
// 	)
// 	require.Nil(t, err)

// 	d := client.Database("test")
// 	c := d.Collection("test")

// 	msg := new(dns.Msg)
// 	_, err = json.Marshal(msg)
// 	require.Nil(t, err)

// 	res, err := c.InsertOne(context.Background(), msg)
// 	fmt.Println(res, err)
// }

func TestMongoStorageHandler_Open(t *testing.T) {
	disableLog()

	// setup
	msh := &storage.MongoStorageHandler{
		Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
			c := GetMockedMongoClient()
			return c, nil
		},
		DatabaseName:   "test",
		CollectionName: "test",
	}

	err := msh.Open()
	assert.Nil(t, err)

	err = msh.Close()
	assert.Nil(t, err)
}

func TestMongoStorageHandler_Insert(t *testing.T) {
	disableLog()

	t.Run("client nil", func(t *testing.T) {
		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return nil, nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		assert.NotNil(t, err, "expected error because client is nil")
	})

	t.Run("error on opening connection", func(t *testing.T) {
		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return &MockedMongoClient{}, errors.New("error")
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		assert.NotNil(t, err, "expected error because client is nil")
	})

	t.Run("valid open", func(t *testing.T) {
		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return GetMockedMongoClient(), nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		assert.Nil(t, err, "expect no error on valid client")
	})
}

func TestMongoStorageHandler_Store(t *testing.T) {
	disableLog()

	t.Run("error on store before open", func(t *testing.T) {
		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return nil, nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Store(nil)
		assert.NotNil(t, err, "expected error because client is nil")
	})

	t.Run("database nil", func(t *testing.T) {
		client := &MockedMongoClient{}
		client.On("Database", mock.Anything).Return(nil)
		client.On("Disconnect", mock.Anything).Return(nil)

		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return client, nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		require.Nil(t, err)
		err = msh.Store(nil)
		assert.NotNil(t, err, "expected error because database is not initialized")
	})

	t.Run("collection nil", func(t *testing.T) {
		database := &MockedMongoDatabase{}
		database.On("Collection", mock.Anything).Return(nil)

		client := &MockedMongoClient{}
		client.On("Database", mock.Anything).Return(database)
		client.On("Disconnect", mock.Anything).Return(nil)

		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return client, nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		require.Nil(t, err)
		err = msh.Store(nil)
		assert.NotNil(t, err, "expect error because collection is not initialized")
	})

	t.Run("insert error", func(t *testing.T) {
		collection := &MockedMongoCollection{}
		collection.On("InsertOne", mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("error"))

		database := &MockedMongoDatabase{}
		database.On("Collection", mock.Anything).Return(nil)

		client := &MockedMongoClient{}
		client.On("Database", mock.Anything).Return(database)
		client.On("Disconnect", mock.Anything).Return(nil)

		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return client, nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		require.Nil(t, err)
		err = msh.Store(nil)
		assert.NotNil(t, err, "expect error because insert throws error")
	})

	t.Run("valid store", func(t *testing.T) {
		msh := &storage.MongoStorageHandler{
			Connect: func(ctx context.Context, opts ...*options.ClientOptions) (storage.MongoClient, error) {
				return GetMockedMongoClient(), nil
			},
			DatabaseName:   "test",
			CollectionName: "test",
		}
		err := msh.Open()
		require.Nil(t, err)
		err = msh.Store(nil)
		assert.Nil(t, err, "expect no error on valid store")
	})
}

func TestMongoStorageHandler_Close(t *testing.T) {
	disableLog()

	t.Run("client nil", func(t *testing.T) {
		msh := &storage.MongoStorageHandler{}
		err := msh.Close()
		assert.Nil(t, err, "expect no error on nil client")
	})

	t.Run("disconnect error", func(t *testing.T) {
		client := &MockedMongoClient{}
		client.On("Disconnect", mock.Anything).Return(errors.New("error"))

		msh := &storage.MongoStorageHandler{
			Client: client,
		}
		err := msh.Close()
		assert.NotNil(t, err, "expect error on disconnect error")
	})

	t.Run("valid close", func(t *testing.T) {
		client := &MockedMongoClient{}
		client.On("Disconnect", mock.Anything).Return(nil)

		msh := &storage.MongoStorageHandler{
			Client: client,
		}
		err := msh.Close()
		assert.Nil(t, err, "expect no error on valid close")
	})
}

func TestMongoStorageHandler_New(t *testing.T) {
	disableLog()

	t.Run("valid new", func(t *testing.T) {
		msh := storage.NewDefaultMongoStorageHandler(context.Background(), "test")
		assert.NotNil(t, msh, "expect no error on valid new")
	})
}

func disableLog() {
	logrus.SetOutput(io.Discard)
}
