package scan

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const SCAN_CACHE_TIME = 2 * time.Hour

// ScanRunCache is a cache for scans of a single run, cleared after SCAN_CACHE_TIME if no new scans are added
type ScanRunCache struct {
	RunId     string
	Mutex     *sync.Mutex
	CacheTime time.Duration
	timer     *time.Timer
	// maps identifier to scanId
	Scans map[string]string
}

// AddScan adds a scan to the cache and resets the timer
func (src *ScanRunCache) AddScan(s Scan) {
	src.Mutex.Lock()
	src.Scans[s.GetIdentifier()] = s.GetMetaInformation().ScanId
	src.Mutex.Unlock()

	src.resetTimer()
}

// ContainsScan checks if a scan is in the cache, returns the scanId if found
func (src *ScanRunCache) ContainsScan(s Scan) (string, bool) {
	src.Mutex.Lock()
	defer src.Mutex.Unlock()

	scanId, found := src.Scans[s.GetIdentifier()]
	return scanId, found
}

// resetTimer resets the timer for the cache
func (src *ScanRunCache) resetTimer() {
	if !src.timer.Stop() {
		// drain channel
		<-src.timer.C
	}
	src.timer.Reset(src.CacheTime)
}

// NewScanRunContainer creates a new ScanRunCache, the timer is started
func NewScanRunContainer(runId string) *ScanRunCache {
	t := time.NewTimer(SCAN_CACHE_TIME)

	src := &ScanRunCache{
		RunId:     runId,
		Mutex:     &sync.Mutex{},
		CacheTime: SCAN_CACHE_TIME,
		timer:     t,
		Scans:     make(map[string]string),
	}

	go func() {
		// once the timer expires we clear the cache
		<-t.C
		logrus.Infof("scan run %s expired, clearing cache", runId)

		src.Mutex.Lock()
		src.Scans = make(map[string]string)
		src.Mutex.Unlock()
	}()

	return src
}

// ScanCache is a cache for scans
type ScanCache struct {
	// maps runsId to identifier to scanId
	Scans map[string]*ScanRunCache
}

// AddScan adds a scan to the run cache and resets the timer
func (cs *ScanCache) AddScan(s Scan) {
	src, found := cs.Scans[s.GetMetaInformation().RunId]
	if !found {
		src = NewScanRunContainer(s.GetMetaInformation().RunId)
		cs.Scans[s.GetMetaInformation().RunId] = src
	}

	src.Scans[s.GetIdentifier()] = s.GetMetaInformation().ScanId
	src.timer.Reset(SCAN_CACHE_TIME)
}

// ContainsScan checks if a scan is in the run cache, returns the scanId if found
func (cs *ScanCache) ContainsScan(s Scan) (string, bool) {
	src, found := cs.Scans[s.GetMetaInformation().RunId]
	if !found {
		return "", false
	}

	return src.ContainsScan(s)
}

// NewScanCache creates a new ScanCache
func NewScanCache() *ScanCache {
	return &ScanCache{
		Scans: make(map[string]*ScanRunCache),
	}
}
