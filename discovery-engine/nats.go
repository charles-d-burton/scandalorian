package main

import (
	"errors"

	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn    *nats.Conn
	Sub     *nats.Subscription
	PubChan chan []byte
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
	natsConn.PubChan = make(chan []byte, 100)
	return nil
}

//Publish push messages to NATS
/*func (natsConn *NatsConn) Publish(topic string, scan *Scan) error {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	log.Infof("Publishing scan: %v to topic: %v", scan, topic)
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	err = natsConn.Conn.Publish(topic, data)
	return err
}*/

func (natsConn *NatsConn) GetPubChan() (chan []byte, error) {
	if natsConn.PubChan == nil {
		return nil, errors.New("publish channel undefined")
	}
	return natsConn.PubChan, nil
}

//Subscribe subscribe to a topic in NATS TODO: Switch to encoded connections
func (natsConn *NatsConn) Subscribe(topic string) (chan []byte, error) {
	log.Infof("Listening on topic: %v", topic)
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
