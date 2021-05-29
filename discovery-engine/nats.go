package main

import (
	"errors"

	jsoniter "github.com/json-iterator/go"
	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn *nats.Conn
	Sub  *nats.Subscription
}

//Connect to the NATS message queue
func (natsConn *NatsConn) Connect(host, port string, errChan chan error) {
	log.Info("Connecting to NATS: ", host, ":", port)
	nh := "nats://" + host + ":" + port
	conn, err := nats.Connect(nh,
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			errChan <- err
		}),
		nats.DisconnectHandler(func(_ *nats.Conn) {
			errChan <- errors.New("unexpectedly disconnected from nats")
		}),
	)
	if err != nil {
		errChan <- err
		return
	}
	natsConn.Conn = conn
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(topic string, scan *Scan, errChan chan error) {
	log.Infof("Publishing scan: %v to topic: %v", scan, topic)
	data, err := json.Marshal(scan)
	if err != nil {
		errChan <- err
		return
	}
	err = natsConn.Conn.Publish(topic, data)
	if err != nil {
		errChan <- err
		return
	}
}

//Subscribe subscribe to a topic in NATS TODO: Switch to encoded connections
func (natsConn *NatsConn) Subscribe(topic string, errChan chan error) chan []byte {
	log.Infof("Listening on topic: %v", topic)
	ch := make(chan *nats.Msg, 64)
	//This might seem redundant but it allows us to have an interface that can be satisfied by other message busses e.g. Rabbit
	sub, err := natsConn.Conn.ChanSubscribe(topic, ch)
	if err != nil {
		errChan <- err
		return nil
	}
	natsConn.Sub = sub
	bch := make(chan []byte, 64)
	go func() {
		for msg := range ch {
			bch <- msg.Data
		}
	}() //Handle byte conversion to satisyf interface
	return bch
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Sub.Unsubscribe()
	natsConn.Sub.Drain()
	natsConn.Conn.Close()
}
