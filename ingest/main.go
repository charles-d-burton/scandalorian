package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/charles-d-burton/kanscan/shared"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/viper"
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(scan *Scan) error
}

//ScanRequest object instructing system on how to scan.
type ScanRequest struct {
	ID      string `json:"id,omitempty"`
	Address string `json:"address,omitempty"`
	Host    string `json:"host,omitempty"`
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP      string          `json:"ip"`
	Type    shared.ScanType `json:"type"`
	Request ScanRequest     `json:"scan_request"`
}

func main() {
	v := viper.New()
	v.SetEnvPrefix("ingest")
	v.AutomaticEnv()

	router := gin.Default()
	router.POST("/scan", handlePost)
	router.Run(":9090")
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
	}
	scanRequest.ID = uuid.New().String()
	if err := enQueueRequest(&scanRequest); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
}

func enQueueRequest(scanreq *ScanRequest) error {
	var scans []Scan
	if scanreq.Host != "" {
		addr, err := net.LookupIP(scanreq.Host)
		if err != nil {
			return errors.New("Unknown Host")
		} else {
			fmt.Println("IP address: ", addr)
			for _, address := range addr {
				var scan Scan
				scan.IP = address.String()
				scan.Request = *scanreq
				scan.Type = shared.Discovery
				scans = append(scans, scan)
			}
		}
	} else {
		addrs, err := Hosts(scanreq.Address)
		if err != nil {
			return err
		}
		var scan Scan
		for _, addr := range addrs {
			scan.IP = addr
			scan.Request = *scanreq
			scan.Type = shared.Discovery
			scans = append(scans, scan)
		}

	}
	for _, scan := range scans {
		log.Println(scan)
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
	if len(ips) == 1 {
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
