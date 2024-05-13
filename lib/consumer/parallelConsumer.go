package consumer

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
)

type ParallelEventConsumer interface {
	Consume(ctx context.Context, topic string) (err error)
}

type CreateConsumerFunc func() (EventConsumer, error)

type KafkaParallelConsumer struct {
	ParallelEventConsumer

	CreateConsumer CreateConsumerFunc
	// number of concurrent consumers
	ConcurrentConsumer int
}

type KafkaParallelConsumerConfig struct {
	*KafkaParallelEventConsumerConfig
	*KafkaConsumerConfig
}

func (kpc *KafkaParallelConsumer) Consume(ctx context.Context, topic string) (err error) {
	if kpc.ConcurrentConsumer <= 0 {
		return fmt.Errorf("invalid concurrent consumer number %d", kpc.ConcurrentConsumer)
	}

	if kpc.CreateConsumer == nil {
		return fmt.Errorf("create consumer function not set")
	}

	wg := sync.WaitGroup{}

	// context for shutdown
	ctx, cancel := context.WithCancel(ctx)

	// channel to receive termination signal
	// we want to gracefully shutdown the scanners
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, os.Interrupt, syscall.SIGTERM) // Handle SIGTERM and Ctrl+C

	for i := 0; i < kpc.ConcurrentConsumer; i++ {
		var consumer EventConsumer
		consumer, err = kpc.CreateConsumer()

		if err != nil {
			logrus.Errorf("failed to create consumer number %d", i)
			cancel()
			break
		}

		if consumer == nil {
			logrus.Errorf("got nil consumer number %d", i)
			err = fmt.Errorf("got nil consumer")
			cancel()
			break
		}

		wg.Add(1)

		go func() {
			defer wg.Done()
			err = consumer.Consume(ctx, topic)
			if err != nil {
				// TODO restart consumer?
				logrus.Errorf("failed to consume topic %s: %v", topic, err)
				cancel()
			}
			consumer.Close()
		}()
	}

	// graceful shutdown handling
	go func() {
		<-termChan
		cancel() // cancel the context to signal consumers to stop
	}()

	wg.Wait()
	logrus.Info("gracefully exit")

	return
}

type KafkaParallelEventConsumerConfig struct {
	ConcurrentConsumer int
}

func NewKafkaParallelEventConsumer(createConsumer CreateConsumerFunc, config *KafkaParallelEventConsumerConfig) (kec *KafkaParallelConsumer, err error) {
	if config == nil {
		return nil, fmt.Errorf("no config provided")
	}

	if config.ConcurrentConsumer <= 0 {
		return nil, fmt.Errorf("invalid concurrent consumer number %d, must be greater or equal 0", config.ConcurrentConsumer)
	}

	if createConsumer == nil {
		return nil, fmt.Errorf("create consumer function not set")
	}

	kec = &KafkaParallelConsumer{
		ConcurrentConsumer: config.ConcurrentConsumer,
	}

	kec.CreateConsumer = createConsumer

	return
}
