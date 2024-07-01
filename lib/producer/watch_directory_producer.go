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

const WAIT_UNTIL_EXIT_TAILING = 60 * time.Minute

type NewScan func(host string, runId string, vantagePoint string) scan.Scan

type WatchDirectoryProducer struct {
	NewScan  NewScan
	Producer ScanProducer

	WaitUntilExit time.Duration
}

func (dp *WatchDirectoryProducer) WatchAndProduce(ctx context.Context, dir, topic, vantagePoint string) error {
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

		watchedFiles := make(map[string]context.CancelFunc)
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
				switch event.Op {
				// we also include chmod since docker bind mounts will have sometimes only chmod instead of create on file creation
				case fsnotify.Create:
					logrus.Infof("new file event %s for %s", event.Op, event.Name)

					if _, ok := watchedFiles[event.Name]; ok {
						logrus.Infof("file already watched, will ignore: %s", event.Name)
						continue
					}

					// let's create a cancel function for this file, so we can stop tailing it if file gets deleted
					childCtx, cancel := context.WithCancel(ctx)

					watchedFiles[event.Name] = cancel
					wg.Add(1)

					var err error
					go func() {
						err = dp.produceFromFile(childCtx, &wg, topic, vantagePoint, event.Name, dp.WaitUntilExit)
					}()
					if err != nil {
						logrus.Errorf("failed to tail file: %v", err)
					}
				case fsnotify.Remove, fsnotify.Rename:
					if cancel, ok := watchedFiles[event.Name]; ok {
						logrus.Infof("tailed file got removed or renamed, will stop tailing now: %s", event.Name)
						cancel()
						delete(watchedFiles, event.Name)
					}
				default:
					logrus.Debugf("got event in directory %s, will ignore: %s", dir, event)
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
func (dp *WatchDirectoryProducer) produceFromFile(ctx context.Context, outerWg *sync.WaitGroup, topic string, vantagePoint string, filepath string, timeAfterExit time.Duration) error {
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
	defer tailChannel.Cleanup()
	defer tailChannel.Dead()

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
				logrus.Debugf("got line from tail: %v", line)
				if line != nil {
					logrus.Debugf("read line %s, use it for scan host", line.Text)

					// update last read line
					lastReadLine = time.Now()

					s := dp.NewScan(line.Text, runId, vantagePoint)

					// produce scan
					producerChannel <- s

					logrus.Debugf("added line %s to producerChannel", line.Text)
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
			if err := dp.Producer.Produce(s, topic); err != nil {
				logrus.Errorf("failed to produce scan in topic %s: %v", topic, err)
			}
			logrus.Debugf("produced scan in topic %s", topic)
		}

		logrus.Debugf("producer channel for file %s closed", filepath)

		flushCounter := 0
		for dp.Producer.Flush(1000) > 0 {
			flushCounter++
			logrus.Info("still waiting for events to be flushed")
			if flushCounter > 10 {
				logrus.Warn("flushing takes too long, exiting")
				break
			}
		}
	}()

	wg.Wait()

	logrus.Debugf("stopped tailing file %s", filepath)

	return nil
}

func NewWatchDirectoryProducer(newScan NewScan, producer ScanProducer) *WatchDirectoryProducer {
	return &WatchDirectoryProducer{
		NewScan:       newScan,
		Producer:      producer,
		WaitUntilExit: WAIT_UNTIL_EXIT_TAILING,
	}
}
