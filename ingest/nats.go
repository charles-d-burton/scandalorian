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

	return natsConn.createStream()
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(scan *Scan) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	log.Info("Publishing scan: ", string(data))
	msg, err := natsConn.JS.Publish(scan.Subject, data)
	log.Debugf("published to %q", msg.Stream)
	return err
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Conn.Close()
}

//Setup the streams
func (natsConn *NatsConn) createStream() error {
	stream, err := natsConn.JS.StreamInfo(streamName)
	if err != nil {
		log.Error(err)
	}
	natsConfig := &nats.StreamConfig{
		Name:     streamName,
		Subjects: streamContexts,
	}
	if stream == nil {
		log.Infof("creating stream %q and subjects %q", streamName, streamContexts)
		_, err := natsConn.JS.AddStream(natsConfig)
		if err != nil {
			return err
		}
	} else {
		log.Infof("updating stream %q and subjects %q", streamName, streamContexts)
		_, err := natsConn.JS.UpdateStream(natsConfig)
		if err != nil {
			return err
		}
	}
	return nil
}
