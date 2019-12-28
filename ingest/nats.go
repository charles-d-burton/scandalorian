package main

import (
	"encoding/json"

	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn *nats.Conn
}

//Connect to the NATS message queue
func (natsConn *NatsConn) Connect(host, port string) error {
	log.Info("Connecting to NATS: ", host, ":", port)
	nh := "nats://" + host + ":" + port
	conn, err := nats.Connect(nh)
	if err != nil {
		return err
	}
	natsConn.Conn = conn
	return nil
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(scan *Scan) error {
	log.Info("Publishing scan: ", scan)
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	err = natsConn.Conn.Publish(enqueueTopic, data)
	return err
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Conn.Close()
}
