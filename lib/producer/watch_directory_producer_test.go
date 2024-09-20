package producer_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/helper"
	"github.com/steffsas/doe-hunter/lib/kafka"
	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	k "github.com/confluentinc/confluent-kafka-go/v2/kafka"
)

type mockedScanProducer struct {
	mock.Mock
}

func (m *mockedScanProducer) Produce(s scan.Scan, topic string) error {
	args := m.Called(s, topic)
	return args.Error(0)
}

func (m *mockedScanProducer) Close() {
	m.Called()
}

func (m *mockedScanProducer) Flush(timeout int) int {
	args := m.Called(timeout)
	return args.Int(0)
}

func (m *mockedScanProducer) Events() chan k.Event {
	args := m.Called()
	return args.Get(0).(chan k.Event)
}

func (m *mockedScanProducer) WatchEvents() {
	m.Called()
}

func newKafkaProducerFactory(prod producer.ScanProducer) func() (producer.ScanProducer, error) {
	return func() (producer.ScanProducer, error) {
		return prod, nil
	}
}

func TestWatchDirectoryProducer_WatchAndProduce(t *testing.T) {
	t.Parallel()

	vp := "test-vp"
	ipVersion := "ipv4"

	newScans := producer.GetProducibleScansFactory(vp, ipVersion)

	t.Run("valid watch and produce on single file", func(t *testing.T) {
		t.Parallel()

		host := "8.8.8.8"

		tmp, err := os.MkdirTemp("", "tests-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tmp)

		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)

		mkp := &mockedScanProducer{}
		mkp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mkp.On("Flush", mock.Anything).Return(0)
		mkp.On("Close", mock.Anything).Return(nil)
		mkp.On("Events").Return(make(chan k.Event))
		mkp.On("WatchEvents").Return()

		dp := &producer.WatchDirectoryProducer{
			GetProducibleScans: newScans,
			NewProducer:        newKafkaProducerFactory(mkp),
			WaitUntilExit:      producer.WAIT_UNTIL_EXIT_TAILING,
		}

		go createFileAndWrite(ctx, tmp, host, "", false)

		go func() {
			time.Sleep(5000 * time.Millisecond)
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp))
		// mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp))
		calls := mkp.Calls

		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 1)

		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				meta := s.GetMetaInformation()
				require.Equal(t, meta.VantagePoint, vp)

				gotScanType := false
				if ddrScan, ok := s.(*scan.DDRScan); ok {
					require.Equal(t, ddrScan.Query.Host, host)
					require.Equal(t, ddrScan.Meta.IpVersion, ipVersion)
					gotScanType = true
				}

				if canaryScan, ok := s.(*scan.CanaryScan); ok {
					require.Equal(t, canaryScan.Query.Host, host)
					require.Equal(t, canaryScan.Meta.IpVersion, ipVersion)
					gotScanType = true
				}

				assert.True(t, gotScanType, "should have produced either DDR or canary scans")
			}
		}
	})

	t.Run("valid watch and produce on multiple files", func(t *testing.T) {
		t.Parallel()

		tmp, err := os.MkdirTemp("", "tests-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tmp)

		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)

		mkp := &mockedScanProducer{}
		mkp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mkp.On("Flush", mock.Anything).Return(0)
		mkp.On("Close", mock.Anything).Return(nil)
		mkp.On("Events").Return(make(chan k.Event))
		mkp.On("WatchEvents").Return()

		dp := &producer.WatchDirectoryProducer{
			GetProducibleScans: newScans,
			NewProducer:        newKafkaProducerFactory(mkp),
			WaitUntilExit:      producer.WAIT_UNTIL_EXIT_TAILING,
		}

		firstHost := "8.8.8.8"
		secondHost := "1.1.1.1"

		// crate and write to files
		go createFileAndWrite(ctx, tmp, firstHost, "", false)
		go createFileAndWrite(ctx, tmp, secondHost, "", false)

		go func() {
			time.Sleep(5000 * time.Millisecond)
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp))
		// mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp))
		calls := mkp.Calls
		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 2*4)

		gotFirstHost := false
		gotSecondHost := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				// it is okay to just test for DDR scan
				if ddrScan, ok := s.(*scan.DDRScan); ok {
					require.Equal(t, ddrScan.Meta.VantagePoint, vp)
					require.Contains(t, []string{firstHost, secondHost}, ddrScan.Query.Host)

					// check if we have both hosts
					switch ddrScan.Query.Host {
					case firstHost:
						gotFirstHost = true
					case secondHost:
						gotSecondHost = true
					}
				}
			}
		}

		require.True(t, gotFirstHost, "should have produced a scan for first host")
		require.True(t, gotSecondHost, "should have produced a scan for second host")
	})

	t.Run("remove and recreate file", func(t *testing.T) {
		t.Parallel()

		tmp, err := os.MkdirTemp("", "tests-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tmp)

		firstHost := "8.8.8.8"
		secondHost := "1.1.1.1"
		filename := "test.csv"

		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		firstCtx, firstCancel := context.WithCancel(ctx)
		secondCtx, secondCancel := context.WithCancel(ctx)

		mkp := &mockedScanProducer{}
		mkp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mkp.On("Flush", mock.Anything).Return(0)
		mkp.On("Close", mock.Anything).Return(nil)
		mkp.On("Events").Return(make(chan k.Event))
		mkp.On("WatchEvents").Return()

		dp := &producer.WatchDirectoryProducer{
			GetProducibleScans: newScans,
			NewProducer:        newKafkaProducerFactory(mkp),
			WaitUntilExit:      producer.WAIT_UNTIL_EXIT_TAILING,
		}

		go createFileAndWrite(firstCtx, tmp, firstHost, filename, true)

		go func() {
			time.Sleep(3000 * time.Millisecond)
			firstCancel()
			time.Sleep(1000 * time.Millisecond)
			go createFileAndWrite(secondCtx, tmp, secondHost, filename, true)
			time.Sleep(1000 * time.Millisecond)
			secondCancel()
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp))
		// mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp))
		calls := mkp.Calls
		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 2*2)

		gotFirstHost := false
		gotSecondHost := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				// it is okay to just test for DDR scan
				if ddrScan, ok := s.(*scan.DDRScan); ok {
					require.True(t, ok)

					require.Equal(t, ddrScan.Meta.VantagePoint, vp)
					require.Contains(t, []string{firstHost, secondHost}, ddrScan.Query.Host)

					// check if we have both hosts
					switch ddrScan.Query.Host {
					case firstHost:
						gotFirstHost = true
					case secondHost:
						gotSecondHost = true
					}
				}
			}
		}

		require.True(t, gotFirstHost, "should have produced a scan for first host")
		require.True(t, gotSecondHost, "should have produced a scan for second host")
	})

	t.Run("quit exiting", func(t *testing.T) {
		t.Parallel()

		tmp, err := os.MkdirTemp("", "tests-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
			return
		}
		defer os.RemoveAll(tmp)

		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)

		subCtx, subCancel := context.WithCancel(ctx)

		mkp := &mockedScanProducer{}
		mkp.On("Produce", mock.Anything, mock.Anything).Return(nil)
		mkp.On("Flush", mock.Anything).Return(0)
		mkp.On("Close", mock.Anything).Return(nil)
		mkp.On("Events").Return(make(chan k.Event))
		mkp.On("WatchEvents").Return()

		dp := &producer.WatchDirectoryProducer{
			GetProducibleScans: newScans,
			NewProducer:        newKafkaProducerFactory(mkp),
			WaitUntilExit:      500 * time.Millisecond,
		}

		firstHost := "8.8.8.8"
		secondHost := "1.1.1.1"

		go createFileAndWrite(subCtx, tmp, firstHost, "", false)
		go createFileAndWrite(subCtx, tmp, secondHost, "", false)

		go func() {
			time.Sleep(3000 * time.Millisecond)
			subCancel()
		}()

		go func() {
			time.Sleep(2000 * time.Millisecond)
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_DDR_TOPIC, vp))
		// mkp.AssertCalled(t, "Produce", mock.Anything, helper.GetTopicFromNameAndVP(kafka.DEFAULT_CANARY_TOPIC, vp))
		calls := mkp.Calls
		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 2*2)

		gotFirstHost := false
		gotSecondHost := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				if ddrScan, ok := s.(*scan.DDRScan); ok {
					require.True(t, ok)

					require.Equal(t, ddrScan.Meta.VantagePoint, vp)
					require.Contains(t, []string{firstHost, secondHost}, ddrScan.Query.Host)

					// check if we have both hosts
					switch ddrScan.Query.Host {
					case firstHost:
						gotFirstHost = true
					case secondHost:
						gotSecondHost = true
					}
				}
			}
		}

		require.True(t, gotFirstHost, "should have produced a scan for first host")
		require.True(t, gotSecondHost, "should have produced a scan for second host")
	})
}

func createFileAndWrite(ctx context.Context, tmpFolder string, lineContent string, optionalFileName string, deleteOnClose bool) {
	if optionalFileName == "" {
		optionalFileName = "test-*.csv"
	}
	f, err := os.CreateTemp(tmpFolder, optionalFileName)
	if err != nil {
		return
	}
	defer f.Close()
	defer func() {
		if deleteOnClose {
			os.Remove(f.Name())
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, err = f.WriteString(fmt.Sprintf("%s\n", lineContent))
			if err != nil {
				return
			}
			// flush to disk
			f.Sync()
			// simulate waiting for new data
			time.Sleep(100 * time.Millisecond)
		}
	}
}
