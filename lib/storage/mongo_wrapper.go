package storage

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoCollectionWrapper struct {
	Collection *mongo.Collection
}

func (mcw *MongoCollectionWrapper) InsertOne(ctx context.Context, document interface{}, opts ...*options.InsertOneOptions) (*mongo.InsertOneResult, error) {
	return mcw.Collection.InsertOne(ctx, document, opts...)
}

type MongoDatabaseWrapper struct {
	Database *mongo.Database
}

func (mdw *MongoDatabaseWrapper) Collection(name string) MongoCollection {
	c := mdw.Database.Collection(name)
	return c
}

type MongoClientWrapper struct {
	Client *mongo.Client
}

func (mcw *MongoClientWrapper) Database(name string, opts ...*options.DatabaseOptions) MongoDatabase {
	d := mcw.Client.Database(name, opts...)
	return &MongoDatabaseWrapper{Database: d}
}

func (mcw *MongoClientWrapper) Disconnect(ctx context.Context) error {
	if mcw.Client != nil {
		return mcw.Client.Disconnect(ctx)
	}
	return nil
}
