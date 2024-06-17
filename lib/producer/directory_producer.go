package producer

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hpcloud/tail"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/scan"
	"gopkg.in/fsnotify.v1"
)

const WAIT_UNTIL_EXIT_TAILING = 30 * time.Minute

type NewScan func(host string, runId string, vantagePoint string) scan.Scan

type DirectoryProducer struct {
	NewScan  NewScan
	Producer EventProducer

	WaitUntilExit time.Duration
}

func (dp *DirectoryProducer) WatchAndProduce(ctx context.Context, dir, topic, vantagePoint string) error {
	// watch the folder and spawn new producer for each file
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.Errorf("failed to create watcher: %v", err)
		return err
	}
	err = watcher.Add(dir)
	if err != nil {
		logrus.Errorf("failed to watch folder: %v", err)
		return err
	}

	// terminate channel
	terminateChan := make(chan os.Signal, 1)
	signal.Notify(terminateChan, os.Interrupt)

	// create cancel context
	ctx, cancel := context.WithCancel(ctx)

	wg := sync.WaitGroup{}
	wg.Add(1)

	// start watching for new files in directory
	go func() {
		defer wg.Done()
		for {
			select {
			case <-terminateChan:
				watcher.Close()
				cancel()
				return
			case <-ctx.Done():
				watcher.Close()
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				logrus.Debugf("got event in directory %s: %s", dir, event)
				if event.Op == fsnotify.Create {
					logrus.Infof("new file with name servers created, will tail now: %s", event.Name)
					wg.Add(1)

					var err error
					go func() {
						err = dp.produceFromFile(ctx, &wg, topic, vantagePoint, event.Name, dp.WaitUntilExit)
					}()
					if err != nil {
						logrus.Errorf("failed to tail file: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logrus.Errorf("error watching directory: %v", err)
			}
		}
	}()

	wg.Wait()

	dp.Producer.Close()

	return nil
}

// timeAfterExit is a timer that exits this process if no new data is written to the file
func (dp *DirectoryProducer) produceFromFile(ctx context.Context, outerWg *sync.WaitGroup, topic string, vantagePoint string, filepath string, timeAfterExit time.Duration) error {
	defer outerWg.Done()

	// tail the output file (will contain IP addresses for scanning)
	tailChannel, err := tail.TailFile(filepath, tail.Config{
		Follow:    true,
		MustExist: true,
	})
	if err != nil {
		logrus.Errorf("failed to tail (watch) output file: %v", err)
		return err
	}

	// create runId to group scans for this file
	runId := uuid.New().String()

	// create producer channel
	producerChannel := make(chan scan.Scan)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		// remember the time of the last read line
		lastReadLine := time.Now()

		for {
			select {
			case <-ctx.Done():
				close(producerChannel)
				return
			case line := <-tailChannel.Lines:
				if line != nil {
					logrus.Infof("got line for scan: %s", line.Text)

					// update last read line
					lastReadLine = time.Now()

					s := dp.NewScan(line.Text, runId, vantagePoint)

					// produce scan
					producerChannel <- s
				}
			default:
				// check if we should exit
				if time.Since(lastReadLine) > timeAfterExit {
					logrus.Info("no new data written to file, exit tailing")
					close(producerChannel)
					return
				}
			}
		}
	}()

	// produce scans
	go func() {
		defer wg.Done()

		// quits when producerChannel is closed and drained
		for s := range producerChannel {
			b, err := s.Marshall()
			if err != nil {
				logrus.Errorf("failed to marshall scan: %v", err)
				continue
			}

			if err := dp.Producer.Produce(b, topic); err != nil {
				logrus.Errorf("failed to produce scan in topic %s: %v", topic, err)
			}
			logrus.Debugf("produced scan in topic %s", topic)
		}
	}()

	wg.Wait()
	return nil
}

func NewDirectoryProducer(producer EventProducer) *DirectoryProducer {
	return &DirectoryProducer{
		Producer: producer,
	}
}
