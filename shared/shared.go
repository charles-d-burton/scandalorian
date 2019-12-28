package shared

//ScanType represents the type of scan to run
type ScanType int

//Declare enums for scan types
const (
	Discovery ScanType = iota
	Nmap
)
