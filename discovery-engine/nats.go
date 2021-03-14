package main

import (
	jsoniter "github.com/json-iterator/go"

	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn *nats.Conn
	Sub  *nats.Subscription
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
func (natsConn *NatsConn) Publish(topic string, scan *Scan) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.Infof("Publishing scan: %v to topic: %v", scan, topic)
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	err = natsConn.Conn.Publish(topic, data)
	return err
}

//Subscribe subscribe to a topic in NATS TODO: Switch to encoded connections
func (natsConn *NatsConn) Subscribe(topic string) (chan []byte, error) {
	ch := make(chan *nats.Msg, 64)
	sub, err := natsConn.Conn.ChanSubscribe(topic, ch)
	if err != nil {
		return nil, err
	}
	natsConn.Sub = sub
	bch := make(chan []byte, 64)
	go func() {
		for msg := range ch {
			bch <- msg.Data
		}
	}() //Handle byte conversion to satisyf interface
	return bch, nil
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Sub.Unsubscribe()
	natsConn.Sub.Drain()
	natsConn.Conn.Close()
}
