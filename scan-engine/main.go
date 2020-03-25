package main

import (
	"fmt"

	"github.com/Ullaakut/nmap"
	"github.com/charles-d-burton/kanscan/shared"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	workers      int
	dequeueTopic string
	workQueue    = make(chan *shared.Scan, 10)
	json         = jsoniter.ConfigCompatibleWithStandardLibrary
	//args         = make(map[string]string)
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(scan *shared.Scan) error
	Subscribe(topic string) (chan []byte, error)
	Close()
}

//NMAPWorker Object to run scans
type NMAPWorker struct {
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	v := viper.New()
	v.SetEnvPrefix("engine")
	v.AutomaticEnv()
	if !v.IsSet("port") || !v.IsSet("host") {
		log.Fatal("Must set host and port for message bus")
	}
	if !v.IsSet("dequeue_topic") {
		dequeueTopic = "scan-engine-queue"
	}
	if !v.IsSet("workers") {
		workers = 5
	} else {
		workers = v.GetInt("workers")
		if workers < 1 {
			workers = 5
		}
	}
	//args["vulscanoutput"] = "'{id} | {product} | {version},'"
	//args["vulscanoutput"] = `'<id>{id}</id><product>{product}</product><version>{version}</version>'`
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
	dch, err := bus.Subscribe(dequeueTopic)
	if err != nil {
		log.Fatal(err)
	}
	for data := range dch { //Wait for incoming scan requests
		log.Info(string(data))
		var scan shared.Scan
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
	log.Infof("Starting NMAP Worker %d", id)
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
			if warns != nil && len(warns) > 0 {
				for _, warn := range warns {
					log.Infof("Warning: %v", warn)
				}
			}
			fmt.Println("")
			fmt.Println("")
			data, err := json.Marshal(&result)
			if err != nil {
				log.Errorf("Error marshalling result: %v", err)
			}
			fmt.Println(string(data))
			fmt.Println("")
			/*fmt.Println("")
			fmt.Println("")
			reader := result.ToReader()
			fmt.Println("")
			fmt.Println("")
			fmt.Println(r
			buf, err := xj.Convert(reader)
			if err != nil {
				log.Errorf("Problem converting nmap output: %v", err)
			}
			data := bytes.ReplaceAll(buf.Bytes(), []byte("\"-"), []byte("\""))
			var NmapResult nmapresult
			err := json.Marshal(data, &nmapresult)
			if err != nil {
				log.Errorf("Unable to marshal results: %v", err)
			}
			fmt.Println(string(data))
			fmt.Println("")
			fmt.Println("")*/
		}
	}
	return nil
}
