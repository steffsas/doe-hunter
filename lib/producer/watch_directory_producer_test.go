package producer_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/steffsas/doe-hunter/lib/producer"
	"github.com/steffsas/doe-hunter/lib/query"
	"github.com/steffsas/doe-hunter/lib/scan"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

func newScan(host, runId, vp string) scan.Scan {
	q := query.NewDDRQuery()
	q.Host = host
	return scan.NewDDRScan(q, true, runId, vp)
}

func TestWatchDirectoryProducer_WatchAndProduce(t *testing.T) {
	t.Parallel()

	topic := "test-topic"
	vp := "test-vp"

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

		dp := &producer.WatchDirectoryProducer{
			NewScan:       newScan,
			Producer:      mkp,
			WaitUntilExit: producer.WAIT_UNTIL_EXIT_TAILING,
		}

		go createFileAndWrite(ctx, tmp, host, "", false)

		go func() {
			time.Sleep(2000 * time.Millisecond)
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp, topic, vp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, topic)
		calls := mkp.Calls

		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 4)

		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				ddrScan, ok := s.(*scan.DDRScan)
				require.True(t, ok)

				require.Equal(t, ddrScan.Meta.VantagePoint, vp)
				require.Equal(t, ddrScan.Query.Host, host)
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

		dp := &producer.WatchDirectoryProducer{
			NewScan:       newScan,
			Producer:      mkp,
			WaitUntilExit: producer.WAIT_UNTIL_EXIT_TAILING,
		}

		firstHost := "8.8.8.8"
		secondHost := "1.1.1.1"

		// crate and write to files
		go createFileAndWrite(ctx, tmp, firstHost, "", false)
		go createFileAndWrite(ctx, tmp, secondHost, "", false)

		go func() {
			time.Sleep(2000 * time.Millisecond)
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp, topic, vp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, topic)
		calls := mkp.Calls
		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 2*4)

		gotFirstHost := false
		gotSecondHost := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				ddrScan, ok := s.(*scan.DDRScan)
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

		dp := &producer.WatchDirectoryProducer{
			NewScan:       newScan,
			Producer:      mkp,
			WaitUntilExit: producer.WAIT_UNTIL_EXIT_TAILING,
		}

		go createFileAndWrite(firstCtx, tmp, firstHost, filename, true)

		go func() {
			time.Sleep(2000 * time.Millisecond)
			firstCancel()
			time.Sleep(500 * time.Millisecond)
			go createFileAndWrite(secondCtx, tmp, secondHost, filename, true)
			time.Sleep(500 * time.Millisecond)
			secondCancel()
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp, topic, vp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, topic)
		calls := mkp.Calls
		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 2*2)

		gotFirstHost := false
		gotSecondHost := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				ddrScan, ok := s.(*scan.DDRScan)
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

		dp := &producer.WatchDirectoryProducer{
			NewScan:       newScan,
			Producer:      mkp,
			WaitUntilExit: 500 * time.Millisecond,
		}

		firstHost := "8.8.8.8"
		secondHost := "1.1.1.1"

		go createFileAndWrite(subCtx, tmp, firstHost, "", false)
		go createFileAndWrite(subCtx, tmp, secondHost, "", false)

		go func() {
			time.Sleep(2000 * time.Millisecond)
			subCancel()
		}()

		go func() {
			time.Sleep(1500 * time.Millisecond)
			cancel()
		}()

		err = dp.WatchAndProduce(ctx, tmp, topic, vp)

		require.NoError(t, err)
		mkp.AssertCalled(t, "Produce", mock.Anything, topic)
		calls := mkp.Calls
		// this is just a lower boundary which has to be met, typically there are more calls
		require.GreaterOrEqual(t, len(calls), 2*2)

		gotFirstHost := false
		gotSecondHost := false
		for _, call := range calls {
			if call.Method == "Produce" {
				args := call.Arguments
				s := args.Get(0).(scan.Scan)

				ddrScan, ok := s.(*scan.DDRScan)
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
			time.Sleep(100 * time.Millisecond)
		}
	}
}
