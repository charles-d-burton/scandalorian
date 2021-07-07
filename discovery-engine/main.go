package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	//Using out of tree due to: https://github.com/google/gopacket/issues/698

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/tevino/abool"
	"go.uber.org/ratelimit"
)

/*
 * TODO List:
 * Need to verify that sending interface is IPV4 until I have time to figure out IPV6
 * Pass message along to NMAP scanner engine
 * Decide if a worker pool pattern of scanning multiple IP addresses makes sense.  I suspect it does
   and the refactor I did makes that easier now
 * Implement DecodingLayerParser for a speed gain, this thing is all about speed
 * Consider eBPF rather than libpcap and doing it raw on the wire
*/

const (
	streamName   = "discovery"
	durableName  = "discovery"
	subscription = "discovery.requests"
	publish      = "scan-engine.scans"
	rateLimit    = 1000 //Upper boundary for how fast to scan a host TODO: convert to tunable
	maxSamples   = 50
	maxDuration  = 2 //Average number of seconds a scan is taking,  TODO: should convert to tunable
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string, errChan chan error)
	Subscribe(errChan chan error) chan []byte
	Publish(scan *Scan) error
	Close()
}

//Scan structure to send to message queue for scanning
type Scan struct {
	IP        string      `json:"ip"`
	ScanID    string      `json:"scan_id"`
	RequestID string      `json:"request_id"`
	Ports     []string    `json:"ports,omitempty"`
	Options   ScanOptions `json:"scan_options,omitempty"`
	Errors    []string    `json:"errors,omitempty"`
}

//ScanOptions optional parameters to set for a scan
type ScanOptions struct {
	TopTen      bool `json:"top_ten,omitempty"`
	TopHundred  bool `json:"top_hundred,omitempty"`
	TopThousand bool `json:"top_thousand,omitempty"`
	PPS         int  `json:"pps,omitempty"`
}

func main() {
	errChan := make(chan error, 10)
	//var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.DebugLevel) //TODO: Remember to reset
	v := viper.New()
	v.SetEnvPrefix("engine")
	v.AutomaticEnv()
	if !v.IsSet("port") || !v.IsSet("host") {
		log.Fatal("Must set host and port for message bus")
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
	host := v.GetString("host")
	var bus MessageBus
	if strings.Contains(host, "nats") {
		var nats NatsConn
		bus = &nats
	} else {
		log.Error("Unknown protocol for message bus host")
	}

	bus.Connect(host, v.GetString("port"), errChan)

	go func() {
		messageChan := bus.Subscribe(errChan)
		for message := range messageChan {
			log.Debug("processing scan")
			var scan Scan
			err := json.Unmarshal(message, &scan)
			if err != nil {
				errChan <- err
				break
			}
			err = scan.ProcessRequest(bus)
			if err != nil {
				errChan <- err
				break
			}
		}
	}()

	for err := range errChan {
		bus.Close()
		if err != nil {
			log.Fatal(err)
		}
		log.Error("unkonown error")
		os.Exit(1)
	}
}

func (scan *Scan) ProcessRequest(bus MessageBus) error {
	if len(scan.Ports) == 0 {
		for i := 0; i <= 65535; i++ {
			scan.Ports = append(scan.Ports, strconv.Itoa(i))
		}
	}
	chunks := divPorts(scan.Ports)
	var wg sync.WaitGroup
	results := make(chan []string, len(chunks))
	errs := make(chan error, 100)
	for _, chunk := range chunks {
		wg.Add(1)
		go func(pchunk []string) {
			defer wg.Done()
			router, err := routing.New()
			if err != nil {
				errs <- err
			}
			var ip net.IP
			if ip = net.ParseIP(scan.IP); ip == nil {
				errs <- errors.New("invalid IP")
				return
			} else if ip = ip.To4(); ip == nil {
				errs <- fmt.Errorf("non ipv4 target %s", scan.IP)
				return
			}

			scanner, err := newScanner(ip, router)
			if err != nil {
				errs <- err
				return
			}
			worker, err := newWorker(scanner.Iface)
			defer worker.close()
			if err != nil {
				errs <- err
				return
			}

			discoveredPorts, err := worker.scan(pchunk, scanner)
			if err != nil {
				errs <- err
			}
			if len(discoveredPorts) == 0 {
				return
			}
			results <- discoveredPorts
		}(chunk)
	}
	wg.Wait()
	close(results)
	close(errs)
	errStrings := make([]string, 0)
	for err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	set := make(map[string]bool)
	discoveredPorts := make([]string, 0)
	for ports := range results {
		for _, port := range ports {
			set[port] = true
		}
	}
	for k := range set {
		discoveredPorts = append(discoveredPorts, k)
	}
	if len(discoveredPorts) == 0 {
		log.Infof("Not open ports found for request %s", scan.RequestID)
		errStrings = append(errStrings, "no open ports found")
	}
	scan.Errors = errStrings
	scan.Ports = discoveredPorts

	return bus.Publish(scan)
}

// scanner handles scanning a single IP address.
type Scanner struct {
	// destination, gateway (if applicable), and source IP addresses to use.
	Dst, Gw, Src net.IP
	// iface is the interface to send packets on.
	Iface *net.Interface
}

type ScanWorker struct {
	// iface is the interface to send packets on.
	iface  *net.Interface
	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer

	sampleRateInput chan *time.Time
	samples         []*time.Duration
	cancel          *abool.AtomicBool
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func newScanner(ip net.IP, router routing.Router) (*Scanner, error) {
	s := &Scanner{
		Dst: ip,
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}

	log.Infof("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.Gw, s.Src, s.Iface = gw, src, iface

	return s, nil
}

func newWorker(iface *net.Interface) (*ScanWorker, error) {
	var scanWorker ScanWorker
	scanWorker.opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	scanWorker.buf = gopacket.NewSerializeBuffer()
	scanWorker.iface = iface
	// Open the handle for reading/writing.
	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	scanWorker.handle = handle
	scanWorker.sampleRateInput = make(chan *time.Time, 51)
	scanWorker.cancel = abool.New()
	return &scanWorker, nil
}

// close cleans up the handle.
func (s *ScanWorker) close() {
	s.handle.Close()
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (sw *ScanWorker) getHwAddr(sc *Scanner) (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := sc.Dst
	if sc.Gw != nil {
		arpDst = sc.Gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       sw.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(sw.iface.HardwareAddr),
		SourceProtAddress: []byte(sc.Src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := sw.send(&eth, &arp); err != nil {
		return nil, err
	}

	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := sw.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *ScanWorker) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

// this code is fugly, I need to make it more readable
// scan scans the dst IP address of this scanner.
func (s *ScanWorker) scan(ports []string, sc *Scanner) ([]string, error) {
	//Start the average calculation
	go s.calculateSlidingWindow()
	discoveredPorts := make([]string, 0)
	// First off, get the MAC address we should be sending packets to.
	hwaddr, err := s.getHwAddr(sc)
	if err != nil {
		return nil, err
	}

	// Create the flow we expect returning packets to have, so we can check
	// against it and discard useless packets.
	//ipFlow := gopacket.NewFlow(layers.EndpointIPv4, sc.Dst, sc.Src)
	rl := ratelimit.New(rateLimit) //TODO: stop using constant
	start := time.Now()

	for _, port := range ports {
		// Construct all the network layers we need.
		eth := layers.Ethernet{
			SrcMAC:       s.iface.HardwareAddr,
			DstMAC:       hwaddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip4 := layers.IPv4{
			SrcIP:    sc.Src,
			DstIP:    sc.Dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		min := 10000
		max := 65535
		srcPort := layers.TCPPort(uint16(rand.Intn(max-min) + min)) //Create a random high port
		tcp := layers.TCP{
			SrcPort: srcPort,
			DstPort: 0, // will be incremented during the scan
			SYN:     true,
		}
		tcp.SetNetworkLayerForChecksum(&ip4)
		if s.cancel.IsSet() {
			return discoveredPorts, err
		}
		start = rl.Take() //Use the rate limiter
		pint, err := strconv.Atoi(port)
		if err != nil {
			return discoveredPorts, err
		}
		tcp.DstPort = layers.TCPPort(pint)

		if err := s.send(&eth, &ip4, &tcp); err != nil {
			log.Errorf("error sending to port %v: %v", tcp.DstPort, err)
		}
		// Time out 5 seconds after the last packet we sent.
		if time.Since(start) > time.Second*5 {
			log.Errorf("timed out for %v, assuming we've seen all we can", sc.Dst)
			return discoveredPorts, err
		}

		log.Debugf("Scanning %v on port %d", sc.Dst, pint)
		// Read in the next packet.
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			return discoveredPorts, err
		} else if err != nil {
			log.Errorf("error reading packet: %v", err)
			return discoveredPorts, err
		}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp)
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			log.Debugf("Could not decode layers: %v\n", err)
			continue
		}
		if tcp.SYN && tcp.ACK {
			log.Infof("port %v open", tcp.SrcPort)
			//This is hacky but it's what the library gives me
			discoveredPorts = append(discoveredPorts, (strings.Split(tcp.SrcPort.String(), "(")[0]))
		}
		now := time.Now()
		s.sampleRateInput <- &now
	}
	log.Debug("returning discovered ports")
	return discoveredPorts, nil
}

//Calculate a sliding window average of scan times.  This could likely be optimized better but this will give a "true" average at the expense of computation/memory
func (s *ScanWorker) calculateSlidingWindow() {
	now := time.Now()
	for sampleTime := range s.sampleRateInput {
		diff := sampleTime.Sub(now) //difference last sample with current sample
		now = time.Now()            //reset now so calculation is correct
		if diff > 5 {
			//Outlier, discard
			continue
		}
		//Construct circular buffer of values
		if len(s.samples) >= maxSamples {
			//drop value 0 off and shift left
			copy(s.samples, s.samples[len(s.samples)-maxSamples+1:])
			s.samples = s.samples[:maxSamples-1]
		}
		s.samples = append(s.samples, &diff)
		if len(s.samples) == maxSamples {
			//Buffer is full so let's calculate
			var total float64
			for _, sample := range s.samples {
				total += sample.Seconds()
			}
			avg := total / maxSamples
			log.Debugf("sample rate: %f", avg)
			if avg > maxDuration {
				log.Info("scan is running too slow")
				s.cancel.Set()
			}
		}
		//Probably not necessary, just here for debugging if something goes wrong
		if len(s.samples) > maxSamples {
			log.Info("scan samples exceeded capacity")
			s.samples = s.samples[:maxSamples]
		}
	}
}

//Chunk up the ports to be scanned to work can be done in parallel
func divPorts(ports []string) [][]string {
	chunkSize := 6000
	var divided [][]string
	for i := 0; i < len(ports); i += chunkSize {
		end := i + chunkSize
		if end > len(ports) {
			end = len(ports)
		}
		divided = append(divided, ports[i:end])
	}
	return divided
}
