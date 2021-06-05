package main

import (
	"errors"
	"fmt"
	"math/rand"

	jsoniter "github.com/json-iterator/go"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	log "github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

//TODO:  This needs connection handling logic added. Currently it's pretty rudimentary on failures

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn     *nats.Conn
	StanConn stan.Conn
	//Sub      *nats.Subscription
	Sub stan.Subscription
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

	uniqueID := rand.Intn(1000)

	uniqueClient := fmt.Sprintf("discovery-engine-%d", uniqueID)
	//TODO: Parameterize this
	sc, err := stan.Connect("nats-streaming", uniqueClient, stan.NatsConn(conn))
	if err != nil {
		errChan <- err
		return
	}
	natsConn.StanConn = sc
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(topic string, scan *Scan, errChan chan error) {
	log.Infof("Publishing scan: %v to topic: %v", scan, topic)
	data, err := json.Marshal(scan)
	if err != nil {
		errChan <- err
		return
	}
	err = natsConn.StanConn.Publish(topic, data)
	if err != nil {
		errChan <- err
		return
	}
}

//Subscribe subscribe to a topic in NATS TODO: Switch to encoded connections
func (natsConn *NatsConn) Subscribe(topic string, errChan chan error) chan []byte {
	log.Infof("Listening on topic: %v", topic)
	bch := make(chan []byte, 1)
	sub, err := natsConn.StanConn.Subscribe(topic, func(m *stan.Msg) {
		bch <- m.Data
	}, stan.StartWithLastReceived())
	if err != nil {
		errChan <- err
		return nil
	}
	natsConn.Sub = sub
	return bch
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.StanConn.Close()
	natsConn.Conn.Close()
}
