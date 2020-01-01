package main

import (
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/Ullaakut/nmap"
	"github.com/charles-d-burton/gopacket"
	"github.com/charles-d-burton/gopacket/examples/util"
	"github.com/charles-d-burton/gopacket/layers"
	"github.com/charles-d-burton/gopacket/pcap"
	"github.com/charles-d-burton/gopacket/routing"
	"github.com/charles-d-burton/kanscan/shared"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	workers      int
	dequeueTopic string
	chansByIface = make(map[string]chan *ScanWork)
)

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string) error
	Publish(scan *shared.Scan) error
	Subscribe(topic string) (chan []byte, error)
	Close()
}

//ScanWork holds the info necessary to run a scan
type ScanWork struct {
	Scan *shared.Scan
	GW   net.IP
	Src  net.IP
	Dst  net.IP
}

//PcapWorker Object to run scans
type PcapWorker struct {
	Handle *pcap.Handle   //initialized once so we can reuse it
	Iface  *net.Interface //The iface the worker is bound to
	Reqs   chan *ScanWork //The work queue
	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
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
		dequeueTopic = "ingest-enqueue"
	}
	if !v.IsSet("workers") {
		workers = 5
	} else {
		workers = v.GetInt("workers")
		if workers < 1 {
			workers = 5
		}
	}
	bus, err := connectBus(v)
	if err != nil {
		log.Fatal(err)
	}
	defer bus.Close()
	defer util.Run()
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
		var scan shared.Scan
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
			GW:   gw,
			Src:  src,
			Scan: &scan,
			Dst:  ip,
		}
		i, ok := chansByIface[iface.Name] //Get the right work queue by iface
		if !ok {
			log.Errorf("Interface not found: %v", iface.Name)
		}
		i <- scWork //Drop the wrok in the queue
	}
}

//createWorkerPool generates the worker queues and the workers to process them
func createWorkerPool(workers int) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if inet, ok := addr.(*net.IPNet); ok { //Make sure we ignore loopback
				if !inet.IP.IsLoopback() {
					ch := make(chan *ScanWork, 100)
					chansByIface[iface.Name] = ch
					for w := 1; w <= workers; w++ {
						var worker PcapWorker
						err := worker.initializeWorker(&iface)
						if err != nil {
							return err
						}
						go worker.start(w)
					}
				}
			}
		}
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

//initializeWorker Sets the Pcap values, creates a pcap Handler for the worker thread.
func (worker *PcapWorker) initializeWorker(iface *net.Interface) error {
	log.Infof("Initalizing a PcapWorker for iface: %v", iface.Name)
	worker.opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	worker.buf = gopacket.NewSerializeBuffer()
	worker.Iface = iface
	worker.Reqs = chansByIface[iface.Name]
	handle, err := pcap.OpenLive(iface.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	worker.Handle = handle
	log.Infof("PcapWorker Initialized for iface: %v", iface.Name)
	return nil
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (worker *PcapWorker) getHwAddr(scw *ScanWork) (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := scw.Dst
	if scw.GW != nil {
		arpDst = scw.GW
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       worker.Iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(worker.Iface.HardwareAddr),
		SourceProtAddress: []byte(scw.Src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send (maybe we should?)
	if err := worker.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := worker.Handle.ReadPacketData()
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

func (worker *PcapWorker) start(id int) error {
	log.Infof("Starting PcapWorker for iface: %v", worker.Iface.Name)
	rand.Seed(time.Now().UnixNano())
	min := 10000
	max := 65535
	srcPort := layers.TCPPort(uint16(rand.Intn(max-min) + min)) //Create a random high port
	log.Infof("Setting src port to: %d", srcPort)
	for scw := range worker.Reqs {
		//Scan the desired endpoint
		scw.Scan.Request.Ports = make([]string, 0)
		log.Infof("Received scan Request on PcapWorker for Iface: %v on worker %d", worker.Iface.Name, id)
		// First off, get the MAC address we should be sending packets to.
		hwaddr, err := worker.getHwAddr(scw)
		if err != nil {
			return err
		}
		// Construct all the network layers we need.
		eth := layers.Ethernet{
			SrcMAC:       worker.Iface.HardwareAddr,
			DstMAC:       hwaddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip4 := layers.IPv4{
			SrcIP:    scw.Src,
			DstIP:    scw.Dst,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		tcp := layers.TCP{
			SrcPort: srcPort,
			DstPort: 0, // will be incremented during the scan
			SYN:     true,
		}
		tcp.SetNetworkLayerForChecksum(&ip4)

		// Create the flow we expect returning packets to have, so we can check
		// against it and discard useless packets.
		ipFlow := gopacket.NewFlow(layers.EndpointIPv4, scw.Dst, scw.Src)
		start := time.Now()
		var port = 0
		for {
			// Send one packet per loop iteration until we've sent packets
			// to all of ports [1, 65535].

			if tcp.DstPort < 65535 {
				start = time.Now()
				tcp.DstPort++
				port++
				if err := worker.send(&eth, &ip4, &tcp); err != nil {
					log.Infof("error sending to port %v: %v", tcp.DstPort, err)
				}
			}
			// Time out 5 seconds after the last packet we sent.
			if time.Since(start) > time.Second*5 {
				//log.Infof("timed out for %v, assuming we've seen all we can", scw.Dst)
				break
			}

			// Read in the next packet.
			data, _, err := worker.Handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err != nil {
				log.Infof("error reading packet: %v", err)
				continue
			}

			// Parse the packet.  We'd use DecodingLayerParser here if we
			// wanted to be really fast.
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

			// Find the packets we care about, and print out logging
			// information about them.  All others are ignored.
			if net := packet.NetworkLayer(); net == nil {
				// log.Printf("packet has no network layer")
			} else if net.NetworkFlow() != ipFlow {
				// log.Printf("packet does not match our ip src/dst")
			} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
				// log.Printf("packet has not tcp layer")
			} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
				// We panic here because this is guaranteed to never
				// happen.
				panic("tcp layer is not tcp layer :-/")
			} else if tcp.DstPort != srcPort {
				// log.Printf("dst port %v does not match", tcp.DstPort)
			} else if tcp.RST {
				//log.Printf("  port %v closed", tcp.SrcPort)
			} else if tcp.SYN && tcp.ACK {
				//scw.Scan.Request.Ports = append(scw.Scan.Request.Ports, strconv.Itoa(port))
				log.Infof("For host %v  port %v open by worker %d", scw.Dst, tcp.SrcPort, id)
				scw.Scan.Request.Ports = append(scw.Scan.Request.Ports, (strings.Split(tcp.SrcPort.String(), "(")[0]))
			} else {
				// log.Printf("ignoring useless packet")
			}
		}
		if len(scw.Scan.Request.Ports) > 0 {
			log.Infof("port scan complete, starting vulnerability scan on ports: %v", scw.Scan.Request.Ports)

			//pdef = strings.Join(scw.Scan.Request.Ports, ",")
			scanner, err := nmap.NewScanner(
				nmap.WithTargets(scw.Dst.String()),
				nmap.WithPorts(scw.Scan.Request.Ports...),
				nmap.WithServiceInfo(),
				nmap.WithScripts("./.nmap/vulners.nse"),
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
			log.Info(result.ScanInfo.Services)
			/*for _, host := range result.Hosts {
				log.Infof("Host %s\n", host.Addresses[0])

				for _, port := range host.Ports {
					log.Infof("\tPort %d open service\n", port.ID)
				}
			}*/
			log.Info("Vulnerability scan complete")
		}
	}
	return nil
}

// send sends the given layers as a single packet on the network.
func (worker *PcapWorker) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(worker.buf, worker.opts, l...); err != nil {
		return err
	}
	return worker.Handle.WritePacketData(worker.buf.Bytes())
}
