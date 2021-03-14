package main

import (
	"runtime"

	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	dequeueTopic = "scan-reversedns-queue"
	enqueueTopic = "collector-reversedns-queue"
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(data []byte) error
	Subscribe(topic string) (chan []byte, error)
	Close()
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP    string   `json:"ip"`
	ID    string   `json:"id"`
	Ports []string `json:"ports,omitempty"`
}

var (
	messageBus MessageBus
	workQueue  = make(chan *Scan, 10)
)

//ReverseDNSWorker Object to run scans
type ReverseDNSWorker struct {
}

func main() {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.SetFormatter(&log.JSONFormatter{})
	v := viper.New()
	v.SetEnvPrefix("reversedns")
	v.AutomaticEnv()
	if !v.IsSet("port") || !v.IsSet("host") {
		log.Fatal("Must set host and port for message bus")
	}
	bus, err := connectBus(v)
	if err != nil {
		log.Fatal(err)
	}
	defer bus.Close()
	messageBus = bus
	dch, err := bus.Subscribe(dequeueTopic)
	if err != nil {
		log.Fatal(err)
	}

	err = createWorkerPool(runtime.NumCPU()) //Start the workers
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
		var worker ReverseDNSWorker
		go worker.start(w)
	}
	return nil
}

func (worker *ReverseDNSWorker) start(id int) error {
	log.Infof("Starting ReverseDNS Worker %d", id)
	for msg := range workQueue {
		log.Info("Scan for: ", msg.IP)
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
