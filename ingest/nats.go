package main

import (
	jsoniter "github.com/json-iterator/go"
	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn *nats.Conn
	JS   nats.JetStreamContext
}

//Connect to the NATS message queue
func (natsConn *NatsConn) Connect(host, port string) error {
	log.Info("Connecting to NATS: ", host, ":", port)
	nh := "nats://" + host + ":" + port
	conn, err := nats.Connect(nh, nats.MaxReconnects(5))
	if err != nil {
		return err
	}
	natsConn.Conn = conn

	natsConn.JS, err = conn.JetStream()
	if err != nil {
		return err
	}
	return nil
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(scan *Scan) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	log.Infof("Publishing scan: %s", string(data))
	log.Info("To stream: %s", scan.Stream)
	msg, err := natsConn.JS.Publish(scan.Stream, data)
	if err != nil {
		log.Debug(err)
		return err
	}
	log.Debugf("published to %q", msg.Stream)
	return nil
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Conn.Close()
}
