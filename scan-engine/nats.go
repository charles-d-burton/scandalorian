package main

import (
	"errors"
	"time"

	nats "github.com/nats-io/nats.go"
	log "github.com/sirupsen/logrus"
)

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
		return
	}
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(run *Run) error {
	data, err := json.Marshal(run)
	if err != nil {
		return err
	}
	log.Debugf("Publishing scan: %v to topic: %v", string(data), publish)
	_, err = natsConn.JS.Publish(publish, data)
	if err != nil {
		return err
	}
	return nil
}

/*
 * TODO: There's a bug here where a message needs to be acked back after a scan is finished
 */
//Subscribe subscribe to a topic in NATS
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
			msgs, err := sub.Fetch(workers, nats.MaxWait(10*time.Second))
			if err != nil {
				log.Error(err)
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
	return bch
}

//Close the connection
func (natsConn *NatsConn) Close() {
	natsConn.Conn.Drain()
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
