package main

import (
	"github.com/Ullaakut/nmap"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	streamName      = "scandalorian"
	subscripContext = "engine"
	publishContext  = "collector"
)

var (
	workers   int
	workQueue = make(chan *Scan, 10)
	bus       MessageBus
	//args         = make(map[string]string)
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(data []byte) error
	Subscribe() (chan []byte, error)
	Close()
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP        string      `json:"ip"`
	ScanID    string      `json:"scan_id"`
	RequestID string      `json:"request_id"`
	Ports     []string    `json:"ports,omitempty"`
	Options   ScanOptions `json:"scan_options:omitempty"`
}

//ScanOptions optional parameters to set for a scan
type ScanOptions struct {
	TopTen      bool `json:"top_ten,omitempty"`
	TopHundred  bool `json:"top_hundred,omitempty"`
	TopThousand bool `json:"top_thousand,omitempty"`
	PPS         int  `json:"pps,omitempty"`
}

//NMAPWorker Object to run scans
type NMAPWorker struct {
}

func main() {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.SetFormatter(&log.JSONFormatter{})
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
		level, err := log.ParseLevel(v.GetString("log_level"))
		if err != nil {
			log.SetLevel(log.InfoLevel)
			log.Warn(err)
		} else {
			log.Info("setting log level to debug")
			log.SetLevel(level)
		}
	}
	bus, err := connectBus(v)
	if err != nil {
		log.Fatal(err)
	}
	defer bus.Close()
	//Initialize the worker channels by interface
	err = createWorkerPool(workers)
	if err != nil {
		log.Fatal(err)
	}
	dch, err := bus.Subscribe()
	if err != nil {
		log.Fatal(err)
	}
	for data := range dch { //Wait for incoming scan requests
		log.Info(string(data))
		var scan Scan
		err := json.Unmarshal(data, &scan)
		if err != nil {
			log.Error(err)
			continue
		}
		workQueue <- &scan //publish work
	}
}

//createWorkerPool generates the worker queues and the workers to process them
func createWorkerPool(workers int) error {
	for w := 1; w <= workers; w++ {
		var worker NMAPWorker
		go worker.start(w)
	}
	return nil
}

//Connect to a message bus, this is abstracted to an interface so implementations of other busses e.g. Rabbit are easier
//TODO: Clean this mess up
func connectBus(v *viper.Viper) (MessageBus, error) {
	var bus MessageBus
	if v.IsSet("bus_type") {
		busType := v.GetString("bus_type")
		switch busType {
		case "nats":
			var natsConn NatsConn
			err := natsConn.Connect(v.GetString("host"), v.GetString("port"))
			if err != nil {
				return nil, err
			}
			bus = &natsConn
		default:
			var natsConn NatsConn
			err := natsConn.Connect(v.GetString("host"), v.GetString("port"))
			if err != nil {
				return nil, err
			}
			bus = &natsConn
		}
	} else {
		var natsConn NatsConn
		err := natsConn.Connect(v.GetString("host"), v.GetString("port"))
		if err != nil {
			return nil, err
		}
		bus = &natsConn
	}
	return bus, nil
}

func (worker *NMAPWorker) start(id int) error {
	type Run struct {
		Run       *nmap.Run `json:"nmap_result"`
		IP        string    `json:"ip"`
		ScanID    string    `json:"scan_id"`
		RequestID string    `json:"request_id"`
	}
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.Infof("Starting NMAP Worker %d", id, "waiting for work...")
	for scan := range workQueue {
		if len(scan.Ports) > 0 {
			log.Infof("Scanning ports for host %v with nmap", scan.IP)
			//pdef = strings.Join(scw.Scan.Request.Ports, ",")
			scanner, err := nmap.NewScanner(
				nmap.WithTargets(scan.IP),
				nmap.WithPorts(scan.Ports...),
				nmap.WithServiceInfo(),
				nmap.WithOSDetection(),
				nmap.WithScripts("./scipag_vulscan/vulscan.nse"),
				nmap.WithTimingTemplate(nmap.TimingAggressive),
				// Filter out hosts that don't have any open ports
				nmap.WithFilterHost(func(h nmap.Host) bool {
					// Filter out hosts with no open ports.
					for idx := range h.Ports {
						if h.Ports[idx].Status() == "open" {
							return true
						}
					}

					return false
				}),
			)
			if err != nil {
				log.Fatalf("unable to create nmap scanner: %v", err)
			}
			result, warns, err := scanner.Run()
			if err != nil {
				log.Fatalf("nmap scan failed: %v", err)
			}
			if len(warns) > 0 {
				for _, warn := range warns {
					log.Infof("Warning: %v", warn)
				}
			}
			var run Run
			run.Run = result
			run.ScanID = scan.ScanID
			run.RequestID = scan.RequestID
			data, err := json.Marshal(&run)
			if err != nil {
				log.Errorf("Error marshalling result: %v", err)
			}
			bus.Publish(data)
		}
	}
	return nil
}
