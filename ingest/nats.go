package main

import (
	"fmt"
	"math/rand"

	jsoniter "github.com/json-iterator/go"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/stan.go"
	log "github.com/sirupsen/logrus"
)

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn     *nats.Conn
	StanConn stan.Conn
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

	uniqueID := rand.Intn(1000)

	uniqueClient := fmt.Sprintf("ingest-%d", uniqueID)
	//TODO: Parameterize this
	sc, err := stan.Connect("nats-streaming", uniqueClient, stan.NatsConn(conn))
	if err != nil {
		return err
	}
	natsConn.StanConn = sc
	return nil
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(scan *Scan) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	log.Info("Publishing scan: ", string(data))
	err = natsConn.StanConn.Publish(scan.Topic, data)
	return err
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Conn.Close()
}
