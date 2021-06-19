package main

import (
	"errors"
	"fmt"
	"os"

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
	conn, err := nats.Connect(nh,
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			log.Fatal(err)
			os.Exit(1)
		}),
		nats.DisconnectHandler(func(_ *nats.Conn) {
			log.Fatal(errors.New("unexpectedly disconnected from nats"))
			os.Exit(1)
		}))
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
func (natsConn *NatsConn) Publish(data []byte) error {
	fmt.Println("")
	fmt.Println("")
	fmt.Println(string(data))
	_, err := natsConn.JS.Publish(publishContext, data)
	if err != nil {
		return err
	}
	return nil
}

//Subscribe subscribe to a topic in NATS TODO: Switch to encoded connections
func (natsConn *NatsConn) Subscribe() (chan []byte, error) {
	bch := make(chan []byte, 10)
	log.Infof("Listening on topic: %v.%v", streamName, subscripContext)
	natsConn.JS.Subscribe(subscripContext, func(m *nats.Msg) {
		log.Debug("message received from Jetstream")
		bch <- m.Data
		m.Ack()
	}, nats.Durable(subscripContext), nats.ManualAck())
	return bch, nil
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
	if stream == nil {
		log.Infof("creating stream %q and subjects %q", streamName, []string{publishContext, subscripContext})
		_, err := natsConn.JS.AddStream(&nats.StreamConfig{
			Name:     streamName,
			Subjects: []string{publishContext, subscripContext},
		})
		if err != nil {
			return err
		}
	}
	return nil
}
