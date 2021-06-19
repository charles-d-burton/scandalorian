package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	streamName = "scandalorian"
)

var (
	messageBus     MessageBus
	streamContexts = []string{
		"discovery",
		"zonewalk",
		"reversedns",
	}
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(scan *Scan) error
	Close()
}

//ScanRequest object instructing system on how to scan.
type ScanRequest struct {
	Address   string      `json:"address,omitempty"`
	Host      string      `json:"host,omitempty"`
	PPS       int         `json:"pps,omitempty"`
	ScanTypes []string    `json:"scan_types:omitempty"`
	Options   ScanOptions `json:"scan_options:omitempty"`
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP        string   `json:"ip"`
	ScanID    string   `json:"scan_id"`
	RequestID string   `json:"request_id"`
	Subject   string   `json:"-"`
	Ports     []string `json:"ports,omitempty"`
}

//ScanOptions optional parameters to set for a scan
type ScanOptions struct {
	TopTen      bool `json:"top_ten,omitempty"`
	TopHundred  bool `json:"top_hundred,omitempty"`
	TopThousand bool `json:"top_thousand,omitempty"`
	PPS         int  `json:"pps,omitempty"` //Set rate limiter value
}

func main() {
	log.Info("Starting up")
	log.SetFormatter(&log.JSONFormatter{})
	v := viper.New()
	v.SetEnvPrefix("ingest")
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
	router := gin.Default()
	router.POST("/scan", handlePost)
	router.Run(":9090")
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

func handlePost(c *gin.Context) {
	var scanRequest ScanRequest
	if err := c.ShouldBindJSON(&scanRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if scanRequest.Address == "" && scanRequest.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host or address undefined"})
		return
	} else if scanRequest.Address != "" && scanRequest.Host != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host and address defined"})
		return
	} else if scanRequest.Host != "" && strings.Contains(strings.ToLower(scanRequest.Host), "localhost") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot scan localhost"})
	}
	if scanRequest.Address != "" {
		parts := strings.Split(scanRequest.Address, "/") //Check for CIDR notation
		if len(parts) < 2 {
			scanRequest.Address = scanRequest.Address + "/32"
		} else if len(parts) > 2 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad address"})
			return
		}
		cidrval, err := strconv.Atoi(parts[1])
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if cidrval < 24 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "subnet out of range"})
			return
		}
		ip, _, err := net.ParseCIDR(scanRequest.Address)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if ip.IsLoopback() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot scan loopback"})
			return
		}
		if err := enQueueRequest(&scanRequest); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else if scanRequest.Host != "" {
		addr, err := net.LookupIP(scanRequest.Host)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unknown host"})
			return
		}
		fmt.Println("IP address: ", addr)
		for _, address := range addr {
			var req ScanRequest
			req = scanRequest
			req.Address = address.String()
			if err := enQueueRequest(&scanRequest); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
	}
}

func enQueueRequest(scanreq *ScanRequest) error {
	id := uuid.New().String()
	if len(scanreq.ScanTypes) == 0 {
		scanreq.ScanTypes = streamContexts //TODO:  Do I want to scan everything by default?
	}
	for _, scanType := range scanreq.ScanTypes {
		if subjectInlist(scanType) {
			addrs, err := Hosts(scanreq.Address)
			if err != nil {
				return err
			}
			if len(addrs) > 0 { //Generate lots of scan objects as we're scanning a subnet
				for _, addr := range addrs {
					var scan Scan
					scan.RequestID = id
					scan.ScanID = uuid.New().String()
					scan.IP = addr
					scan.Subject = scanType
					log.Infof("Sending to topic: %s.%s", streamName, scanType)
					err = messageBus.Publish(&scan)
					if err != nil {
						log.Warn(err)
						return err
					}
				}
				return nil
			}
			var scan Scan
			scan.RequestID = id
			scan.ScanID = uuid.New().String()
			scan.IP = scanreq.Address
			scan.Subject = scanType
			log.Infof("Sending to topic: %s.%s", streamName, scanType)
			err = messageBus.Publish(&scan)
			if err != nil {
				log.Warn(err)
				return err
			}
		}
	}
	return nil
}

//Hosts split cidr into individual IP addresses
func Hosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func subjectInlist(subject string) bool {
	for _, value := range streamContexts {
		if subject == value {
			return true
		}
	}
	return false
}
