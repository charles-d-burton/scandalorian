package main

import (
	"net"

	//Using out of tree due to: https://github.com/google/gopacket/issues/698
	"github.com/charles-d-burton/gopacket"
	"github.com/charles-d-burton/gopacket/layers"
	"github.com/charles-d-burton/gopacket/pcap"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	dequeueTopic = "scan-discovery-queue"
	enqueueTopic = "scan-engine-queue"
	rateLimit    = 3000
)

var (
	//bus          MessageBus
	pubChan      chan []byte
	workers      int
	chansByIface = make(map[string]chan *ScanWork, 100)
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	GetPubChan() (chan []byte, error)
	//Publish(topic string, scan *Scan) error
	Subscribe(topic string) (chan []byte, error)
	Close()
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP        string   `json:"ip"`
	ScanID    string   `json:"scan_id"`
	RequestID string   `json:"request_id"`
	Topic     string   `json:"-"`
	Ports     []string `json:"ports,omitempty"`
}

//ScanWork holds the info necessary to run a scan
type ScanWork struct {
	ScanID    string   `json:"scan_id"`
	RequestID string   `json:"request_id"`
	IP        string   `json:"ip"`
	Ports     []string `json:"ports"`
	GW        net.IP
	Src       net.IP
	Dst       net.IP
}

//PcapWorker Object to run scans
type PcapWorker struct {
	Handle  *pcap.Handle   //initialized once so we can reuse it
	Iface   *net.Interface //The iface the worker is bound to
	Reqs    chan *ScanWork //The work queue
	SrcPort layers.TCPPort
	PubChan chan []byte
	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

func main() {
	//var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.DebugLevel) //TODO: Remember to reset
	v := viper.New()
	v.SetEnvPrefix("engine")
	v.AutomaticEnv()
	if !v.IsSet("port") || !v.IsSet("host") {
		log.Fatal("Must set host and port for message bus")
	}
	if !v.IsSet("workers") {
		workers = 5
	} else {
		workers = v.GetInt("workers")
		if workers < 1 {
			workers = 5
		}
	}
	if !v.IsSet("log_level") {
		log.SetLevel(log.InfoLevel)
	} else {
		_, err := log.ParseLevel(v.GetString("log_level"))
		if err != nil {
			log.SetLevel(log.InfoLevel)
			log.Warn(err)
		}
	}
	/*bus, err := connectBus(v)
	if err != nil {
		log.Fatal(err)
	}
	defer bus.Close()
	router, err := routing.New()
	if err != nil {
		//log.Fatal("routing error:", err)
		log.Fatal("router error:", err)
	}
	//Initialize the worker channels by interface
	err = createWorkerPool(workers)
	if err != nil {
		log.Fatal(err)
	}
	dch, err := bus.Subscribe(dequeueTopic)
	if err != nil {
		log.Fatal(err)
	}
	for data := range dch { //Wait for incoming scan requests
		log.Info(string(data))
		var scan Scan
		err := json.Unmarshal(data, &scan)
		if err != nil {
			log.Warn(err)
			continue
		}
		var ip net.IP
		if ip = net.ParseIP(scan.IP); ip == nil {
			log.Printf("non-ip target: %q", scan.IP)
			continue
		} else if ip = ip.To4(); ip == nil {
			log.Printf("non-ipv4 target: %q", scan.IP)
			continue
		}
		iface, gw, src, err := router.Route(ip) //Get the route
		if err != nil {
			log.Info(err)
		}
		scWork := &ScanWork{ //Create full SYN Scan work Object
			GW:        gw,
			Src:       src,
			RequestID: scan.RequestID,
			ScanID:    scan.ScanID,
			IP:        scan.IP,
			Dst:       ip,
		}
		i, ok := chansByIface[iface.Name] //Get the right work queue by iface
		if !ok {
			log.Errorf("Interface not found: %v", iface.Name)
		}
		i <- scWork //Drop the work in the queue
	}*/
}
