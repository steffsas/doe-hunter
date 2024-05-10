package scan

type Scan struct {
	ScanID       string `json:"scan_id"`
	ParentScanID string `json:"parent_scan_id"`
	RootScanID   string `json:"root_scan_id"`

	Host string `json:"host"`
	Port int    `json:"port"`
}
