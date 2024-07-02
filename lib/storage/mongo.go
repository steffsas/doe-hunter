package storage

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const ENV_MONGO_URI = "MONGO_USERNAME"

const DEFAULT_MONGO_URL = "mongodb://root:example@localhost:27017/"

const DEFAULT_DATABASE = "doe"

const DEFAULT_DOT_COLLECTION = "dot-scans"
const DEFAULT_DDR_COLLECTION = "ddr-scans"
const DEFAULT_DOQ_COLLECTION = "doq-scans"
const DEFAULT_DOH_COLLECTION = "doh-scans"
const DEFAULT_PTR_COLLECTION = "ptr-scans"
const DEFAULT_EDSR_COLLECTION = "edsr-scans"
const DEFAULT_CERTIFICATE_COLLECTION = "certificate-scans"
const DEFAULT_FINGERPRINT_COLLECTION = "fingerprint-scans"
const DEFAULT_DDR_DNSSEC_COLLECTION = "ddr-dnssec-scans"

type MongoCollection interface {
	InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error)
}

type MongoDatabase interface {
	Collection(name string) MongoCollection
}

type MongoClient interface {
	Database(name string, opts ...*options.DatabaseOptions) MongoDatabase
	Disconnect(ctx context.Context) error
}

type MongoConnect func(ctx context.Context, opts ...*options.ClientOptions) (MongoClient, error)

type MongoStorageHandler struct {
	StorageHandler

	Connect MongoConnect
	Client  MongoClient

	ConnectionString string
	DatabaseName     string
	CollectionName   string
}

func (msh *MongoStorageHandler) Open() (err error) {
	msh.Client, err = msh.Connect(
		context.Background(),
		options.Client().ApplyURI(msh.ConnectionString),
	)

	if msh.Client == nil {
		return errors.New("mongo client not initialized")
	}

	if err != nil {
		logrus.Errorf("failed to connect to mongo: %v", err)
		return err
	}

	return nil
}

func (msh *MongoStorageHandler) Store(data interface{}) (err error) {
	if msh.Client == nil {
		return errors.New("mongo client not initialized")
	}

	d := msh.Client.Database(msh.DatabaseName)
	if d == nil {
		return errors.New("mongo database not initialized")
	}
	c := d.Collection(msh.CollectionName)
	if c == nil {
		return errors.New("mongo collection not initialized")
	}

	_, err = c.InsertOne(context.Background(), data)

	return
}

func (msh *MongoStorageHandler) Close() (err error) {
	if msh.Client != nil {
		err = msh.Client.Disconnect(context.Background())
		//nolint:errorlint
		if err != nil && err != mongo.ErrClientDisconnected {
			logrus.Errorf("failed to disconnect from mongo: %v", err)
			return err
		}
	}

	return nil
}

func NewDefaultMongoStorageHandler(ctx context.Context, collectionName string, databaseURL string) *MongoStorageHandler {
	ch := &MongoStorageHandler{
		Connect: func(ctx context.Context, opts ...*options.ClientOptions) (MongoClient, error) {
			client, err := mongo.Connect(ctx, opts...)
			if err != nil {
				return nil, err
			}
			return &MongoClientWrapper{Client: client}, nil
		},
		ConnectionString: databaseURL,
		DatabaseName:     DEFAULT_DATABASE,
		CollectionName:   collectionName,
	}

	return ch
}
