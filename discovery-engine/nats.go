package main

import (
	"errors"
	"time"

	jsoniter "github.com/json-iterator/go"
	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

//TODO:  This needs connection handling logic added. Currently it's pretty rudimentary on failures

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn *nats.Conn
	JS   nats.JetStreamContext
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

	natsConn.JS, err = conn.JetStream()
	if err != nil {
		errChan <- err
		return
	}

	err = natsConn.createStream()

	if err != nil {
		errChan <- err
	}
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(scan *Scan) error {
	log.Infof("Publishing scan: %v to topic: %v", scan, publish)
	data, err := json.Marshal(scan)
	if err != nil {
		return err
	}
	_, err = natsConn.JS.Publish(publish, data)
	if err != nil {
		return err
	}
	return nil
}

/*
 * TODO: There's a bug here where a message needs to be acked back after a scan is finished
 */
//Subscribe subscribe to a topic in NATS TODO: Switch to encoded connections
func (natsConn *NatsConn) Subscribe(errChan chan error) chan *Message {
	log.Infof("Listening on topic: %v", subscription)
	bch := make(chan *Message, 1)
	sub, err := natsConn.JS.PullSubscribe(subscription, durableName, nats.PullMaxWaiting(128), nats.ManualAck())
	if err != nil {
		errChan <- err
		return nil
	}
	go func() {
		for {
			msgs, err := sub.Fetch(1, nats.MaxWait(10*time.Second))
			if err != nil {
				log.Error(err)
				//errChan <- err
			}
			for _, msg := range msgs {
				if err != nil {
					errChan <- err
				}
				message := newMessage(msg.Data)
				bch <- message
				ack := message.Processed()
				if !ack {
					msg.Nak()
					continue
				}
				msg.Ack()
			}
		}
	}()

	/*natsConn.JS.Subscribe(subscription, func(m *nats.Msg) {
		log.Debug("message received from Jetstream")
		bch <- m.Data
		err := <-errChan
		if err != nil {
			m.Nak()
			log.Error(err)
			return
		}
		m.Ack()
	}, nats.Durable(durableName), nats.ManualAck())*/
	return bch
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
		Subjects: []string{subscription},
	}
	if stream == nil {
		log.Infof("creating stream %s", subscription)
		_, err := natsConn.JS.AddStream(natsConfig)
		if err != nil {
			return err
		}
	}
	return nil
}

func newMessage(data []byte) *Message {
	var message Message
	message.Data = data
	message.acknowledge = make(chan bool, 1)
	return &message
}

//Ack acknowledge message delivered
func (msg *Message) Ack() {
	msg.acknowledge <- true
}

//Nack acknowledge message processing failure
func (msg *Message) Nak() {
	msg.acknowledge <- false
}

func (msg *Message) Processed() bool {
	return <-msg.acknowledge
}
