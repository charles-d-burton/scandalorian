// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// synscan implements a TCP syn scanner on top of pcap.
// It's more complicated than arpscan, since it has to handle sending packets
// outside the local network, requiring some routing and ARP work.
//
// Since this is just an example program, it aims for simplicity over
// performance.  It doesn't handle sending packets very quickly, it scans IPs
// serially instead of in parallel, and uses gopacket.Packet instead of
// gopacket.DecodingLayerParser for packet processing.  We also make use of very
// simple timeout logic with time.Since.
//
// Making it blazingly fast is left as an exercise to the reader.

package main

import (
	"encoding/json"
	"errors"
	"net"
	"time"

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
	Handle *pcap.Handle
	Iface  *net.Interface
	Reqs   chan *ScanWork
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
	err = createWorkerPool()
	if err != nil {
		log.Fatal(err)
	}
	dch, err := bus.Subscribe(dequeueTopic)
	if err != nil {
		log.Fatal(err)
	}
	for data := range dch {
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
		// Note:  newScanner creates and closes a pcap Handle once for
		// every scan target.  We could do much better
		/*s, err := newScanner(ip, router)
		if err != nil {
			log.Infof("unable to create scanner for %v: %v", ip, err)
			continue
		}
		if err := s.scan(); err != nil {
			log.Infof("unable to scan %v: %v", ip, err)
		}
		s.close()*/
	}
}

func createWorkerPool() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		ch := make(chan *ScanWork, 100)
		chansByIface[iface.Name] = ch
		var worker PcapWorker
		err := worker.initializeWorker(&iface)
		if err != nil {
			return err
		}
		go worker.start() //Start a single worker for now, revisit this later with better error handling
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

// scanner handles scanning a single IP address.
type scanner struct {
	// iface is the interface to send packets on.
	iface *net.Interface
	// destination, gateway (if applicable), and source IP addresses to use.
	dst, gw, src net.IP

	handle *pcap.Handle

	// opts and buf allow us to easily serialize packets in the send()
	// method.
	opts gopacket.SerializeOptions
	buf  gopacket.SerializeBuffer
}

// newScanner creates a new scanner for a given destination IP address, using
// router to determine how to route packets to that IP.
func newScanner(ip net.IP, router routing.Router) (*scanner, error) {
	s := &scanner{
		dst: ip,
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf: gopacket.NewSerializeBuffer(),
	}
	// Figure out the route to the IP.
	iface, gw, src, err := router.Route(ip)
	if err != nil {
		return nil, err
	}
	log.Infof("scanning ip %v with interface %v, gateway %v, src %v", ip, iface.Name, gw, src)
	s.gw, s.src, s.iface = gw, src, iface

	// Open the handle for reading/writing.
	// Note we could very easily add some BPF filtering here to greatly
	// decrease the number of packets we have to look at when getting back
	// scan results.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	s.handle = handle
	return s, nil
}

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

func (worker *PcapWorker) start() error {
	log.Infof("Starting PcapWorker for iface: %v", worker.Iface.Name)
	for scw := range worker.Reqs {
		log.Infof("Received scan Request on PcapWorker for Iface: %v", worker.Iface.Name)
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
			SrcPort: 54321, //TODO: implement logic to create random ports per worker
			DstPort: 0,     // will be incremented during the scan
			SYN:     true,
		}
		tcp.SetNetworkLayerForChecksum(&ip4)

		// Create the flow we expect returning packets to have, so we can check
		// against it and discard useless packets.
		ipFlow := gopacket.NewFlow(layers.EndpointIPv4, scw.Dst, scw.Src)
		start := time.Now()
		for {
			// Send one packet per loop iteration until we've sent packets
			// to all of ports [1, 65535].
			if tcp.DstPort < 65535 {
				start = time.Now()
				tcp.DstPort++
				if err := worker.send(&eth, &ip4, &tcp); err != nil {
					log.Infof("error sending to port %v: %v", tcp.DstPort, err)
				}
			}
			// Time out 5 seconds after the last packet we sent.
			if time.Since(start) > time.Second*5 {
				log.Infof("timed out for %v, assuming we've seen all we can", scw.Dst)
				return nil
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
			} else if tcp.DstPort != 54321 {
				// log.Printf("dst port %v does not match", tcp.DstPort)
			} else if tcp.RST {
				//log.Printf("  port %v closed", tcp.SrcPort)
			} else if tcp.SYN && tcp.ACK {
				log.Infof("  port %v open", tcp.SrcPort)
			} else {
				// log.Printf("ignoring useless packet")
			}
		}
	}
	return nil
}

// close cleans up the handle.
func (s *scanner) close() {
	s.handle.Close()
}

// getHwAddr is a hacky but effective way to get the destination hardware
// address for our packets.  It does an ARP request for our gateway (if there is
// one) or destination IP (if no gateway is necessary), then waits for an ARP
// reply.  This is pretty slow right now, since it blocks on the ARP
// request/reply.
func (s *scanner) getHwAddr() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := s.dst
	if s.gw != nil {
		arpDst = s.gw
	}
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.iface.HardwareAddr),
		SourceProtAddress: []byte(s.src),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(arpDst),
	}
	// Send a single ARP request packet (we never retry a send (maybe we should?)
	if err := s.send(&eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := s.handle.ReadPacketData()
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

// scan scans the dst IP address of this scanner.
func (s *scanner) scan(srcPort layers.TCPPort) error {
	// First off, get the MAC address we should be sending packets to.
	hwaddr, err := s.getHwAddr()
	if err != nil {
		return err
	}
	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := layers.IPv4{
		SrcIP:    s.src,
		DstIP:    s.dst,
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
	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dst, s.src)
	start := time.Now()
	for {
		// Send one packet per loop iteration until we've sent packets
		// to all of ports [1, 65535].
		if tcp.DstPort < 65535 {
			start = time.Now()
			tcp.DstPort++
			if err := s.send(&eth, &ip4, &tcp); err != nil {
				log.Printf("error sending to port %v: %v", tcp.DstPort, err)
			}
		}
		// Time out 5 seconds after the last packet we sent.
		if time.Since(start) > time.Second*5 {
			log.Printf("timed out for %v, assuming we've seen all we can", s.dst)
			return nil
		}

		// Read in the next packet.
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
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
		} else if tcp.DstPort != 54321 {
			// log.Printf("dst port %v does not match", tcp.DstPort)
		} else if tcp.RST {
			//log.Printf("  port %v closed", tcp.SrcPort)
		} else if tcp.SYN && tcp.ACK {
			log.Infof("  port %v open", tcp.SrcPort)
		} else {
			// log.Printf("ignoring useless packet")
		}
	}
}

// send sends the given layers as a single packet on the network.
func (s *scanner) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(s.buf, s.opts, l...); err != nil {
		return err
	}
	return s.handle.WritePacketData(s.buf.Bytes())
}

func (worker *PcapWorker) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(worker.buf, worker.opts, l...); err != nil {
		return err
	}
	return worker.Handle.WritePacketData(worker.buf.Bytes())
}
