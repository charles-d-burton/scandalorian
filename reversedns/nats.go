package main

import (
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
func (natsConn *NatsConn) Publish(data []byte) error {
	return natsConn.Conn.Publish(enqueueTopic, data)
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
	natsConn.Conn.Close()
}
