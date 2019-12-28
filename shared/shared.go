package shared

//ScanType represents the type of scan to run
type ScanType int

//Declare enums for scan types
const (
	Discovery ScanType = iota
	Nmap
)

//ScanRequest object instructing system on how to scan.
type ScanRequest struct {
	ID      string   `json:"id,omitempty"`
	Address string   `json:"address,omitempty"`
	Host    string   `json:"host,omitempty"`
	Ports   []string `json:"ports,omitempty"`
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP      string      `json:"ip"`
	Type    ScanType    `json:"type"`
	Request ScanRequest `json:"scan_request"`
}
