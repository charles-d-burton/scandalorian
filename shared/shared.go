package shared

//ScanType represents the type of scan to run
type ScanType int

//Declare enums for scan types
const (
	Discovery ScanType = iota
	Nmap
)

//TODO: These need rethought a bit
//ScanRequest object instructing system on how to scan.
type ScanRequest struct {
	ID      string `json:"id,omitempty"`
	Address string `json:"address,omitempty"`
	Host    string `json:"host,omitempty"`
	PPS     int    `json:"pps,omitempty"`
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP      string      `json:"ip"`
	Type    ScanType    `json:"type"`
	Ports   []string    `json:"ports,omitempty"`
	Result  string      `json:"result,omitempty"`
	Request ScanRequest `json:"scan_request"`
}

//ReverseDNS structure to perform a reverse DNS lookup
type ReverseDNS struct {
	IP          string            `json:"ip"`
	HostRecords map[string]string `json:"hosts"`
	Request     ScanRequest       `json:"scan_request"`
}

//TODO: This requires more info, need to learn about zonewalking

//Zonewalk structure to perform a zonewalk on a host or IP
type Zonewalk struct {
	IP      string      `json:"ip,omitempty"`
	Request ScanRequest `json:"scan_request"`
}
