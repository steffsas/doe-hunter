package producer

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/containerd/fifo"
	"github.com/google/uuid"
	"github.com/hpcloud/tail"
	"github.com/sirupsen/logrus"
	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"gopkg.in/fsnotify.v1"
)

const WAIT_UNTIL_EXIT_TAILING = 60 * time.Minute

type ProducableScan struct {
	Scan  scan.Scan
	Topic string
}

type GetProduceableScans func(host, runId string) []ProducableScan

type WatchDirectoryProducer struct {
	GetProduceableScans GetProduceableScans
	Producer            ScanProducer

	WaitUntilExit time.Duration
}

func (dp *WatchDirectoryProducer) WatchAndProduce(ctx context.Context, dir string) error {
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

					go func() {
						defer wg.Done()
						errProducer := dp.produceFromFile(childCtx, event.Name, dp.WaitUntilExit)
						if errProducer != nil {
							logrus.Errorf("failed to tail file: %v", err)
						}
					}()
				case fsnotify.Remove, fsnotify.Rename:
					if cancel, ok := watchedFiles[event.Name]; ok {
						logrus.Infof("tailed file got removed or renamed, will stop tailing now: %s", event.Name)
						cancel()
						delete(watchedFiles, event.Name)
					}
				default:
					logrus.Debugf("got event in directory %s, will ignore: %s", dir, event)
				}
			case errWatcher, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logrus.Errorf("error watching directory: %v", errWatcher)
			}
		}
	}()

	wg.Wait()

	dp.Producer.Close()

	return nil
}

// timeAfterExit is a timer that exits this process if no new data is written to the file
func (dp *WatchDirectoryProducer) produceFromFile(ctx context.Context, filepath string, timeAfterExit time.Duration) error {
	// create runId to group scans for this file
	runId := uuid.New().String()

	// check whether file is fifo, see https://linux.die.net/man/3/mkfifo
	pipe, err := fifo.IsFifo(filepath)
	if err != nil {
		logrus.Errorf("failed to check if file %s is a pipe, set pipe to false: %v", filepath, err)
		pipe = false
	} else {
		if pipe {
			logrus.Debugf("file %s is a pipe", filepath)
		} else {
			logrus.Debugf("file %s is not a pipe", filepath)
		}
	}

	// 2^8 = 256 entries, this is the default buffer size
	bufferSize := 1 << 8
	if pipe {
		// size of 2^25 is around 33M entries which is sufficient for containing all expected ips to be found in ipv4
		// we do not want to implement back pressure because this will cause zmap in combination with named pipes in dropping packets/results
		bufferSize = 1 << 25
		logrus.Debugf("since %s is a named pipe, set buffer size to 2^25", filepath)
	}

	// create producer channel
	producerChannel := make(chan string, bufferSize)

	// tail the output file (will contain IP addresses for scanning)
	logrus.Debugf("start tailing file %s", filepath)

	// warning: tailChannel is a buffer of size 1, so make sure to consume it in time otherwise the pipe will block
	tailChannel, err := tail.TailFile(filepath, tail.Config{
		Follow:    true,
		Pipe:      pipe,
		MustExist: true,
	})
	if err != nil {
		logrus.Errorf("failed to tail (watch) output file: %v", err)
		return err
	}
	defer tailChannel.Cleanup()

	stopTailing := func() {
		if err := tailChannel.Stop(); err != nil {
			logrus.Errorf("failed to stop tailing file %s: %v", filepath, err)
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	// tail line worker
	// this is done in a separate go routine to avoid blocking the producer (ZMAP)
	// it reads the lines from the named pipe/file as fast as possible
	go func() {
		defer wg.Done()
		defer close(producerChannel)

		// remember the time of the last read line
		lastReadLine := time.Now()

		counter := 0
		for {
			select {
			case <-ctx.Done():
				return
			case line := <-tailChannel.Lines:
				switch {
				case line == nil:
					logrus.Infof("line nil in %s, exit tailing", filepath)
					stopTailing()
					return
				case line.Err != nil && errors.Is(line.Err, tail.ErrStop):
					logrus.Debugf("tail of %s stopped, exit tailing", filepath)
					return
				case line.Err != nil && errors.Is(line.Err, io.EOF):
					logrus.Debugf("tail of %s reached EOF, exit tailing", filepath)
					stopTailing()
					return
				case line.Text == "":
					logrus.Debugf("empty line in %s, ignore", filepath)
					continue
				default:
					counter++

					// log every 100000 lines
					if counter%100000 == 0 {
						logrus.Debugf("read %d lines from %s", counter, filepath)
						// update last read line
						lastReadLine = time.Now()
						// reset counter
						counter = 0
					}

					// produce scan, line.Text should be an ip address/host to scan
					producerChannel <- line.Text
				}
			default:
				// check if we should exit
				if timeAfterExit > 0 && time.Since(lastReadLine) > timeAfterExit {
					logrus.Info("no new data written to file, exit tailing")
					return
				}
			}
		}
	}()

	// creates and produces scans
	go func() {
		defer wg.Done()

		// so errors are going to be logged asynchronously
		dp.Producer.WatchEvents()
		// quits when producerChannel is closed and drained
		for ip := range producerChannel {
			scans := dp.GetProduceableScans(ip, runId)
			for _, s := range scans {
				if err := dp.Producer.Produce(s.Scan, s.Topic); err != nil {
					logrus.Errorf("failed to produce scan in topic %s: %v", s.Topic, err)
				}
				logrus.Debugf("produced scan in topic %s", s.Topic)
			}
		}

		// wait until queue is flushed
		dp.Producer.Flush(0)
		dp.Producer.Close()

		logrus.Debugf("producer channel for file %s closed", filepath)
	}()

	wg.Wait()

	logrus.Infof("stopped tailing file %s", filepath)

	return nil
}

func GetProduceableScansFactory(vp, ipVersion string) func(host, runId string) []ProducableScan {
	return func(host, runId string) []ProducableScan {
		scans := []ProducableScan{}

		// check if host is on blocklist
		isOnBlocklist := false
		if ip := net.ParseIP(host); ip != nil {
			if helper.BlockedIPs.Contains(ip) {
				isOnBlocklist = true
			}
		}

		// ddr scan
		q := query.NewDDRQuery()
		q.Host = host

		s := scan.NewDDRScan(q, true, runId, vp)
		s.Meta.IpVersion = ipVersion
		s.Meta.IsOnBlocklist = isOnBlocklist

		scans = append(scans, ProducableScan{
			Scan:  s,
			Topic: helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp),
		})

		// disable canary scans
		// // canary scans
		// for _, domain := range scan.CANARY_DOMAINS {
		// 	q := query.NewCanaryQuery(domain, host)
		// 	s := scan.NewCanaryScan(q, runId, vp)
		// 	s.Meta.IpVersion = ipVersion
		// 	s.Meta.IsOnBlocklist = isOnBlocklist

		// 	scans = append(scans, ProducableScan{
		// 		Scan:  s,
		// 		Topic: helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp),
		// 	})
		// }

		return scans
	}
}

func NewWatchDirectoryProducer(newScans GetProduceableScans, producer ScanProducer) *WatchDirectoryProducer {
	return &WatchDirectoryProducer{
		GetProduceableScans: newScans,
		Producer:            producer,
		WaitUntilExit:       WAIT_UNTIL_EXIT_TAILING,
	}
}
