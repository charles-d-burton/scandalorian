package main

import nats "github.com/nats-io/nats.go"

//NatsConn struct to satisfy the interface
type NatsConn struct {
	Conn nats.Conn
}

//Connect to the NATS message queue
func (natsConn *NatsConn) Connect(host, port string) error {
	return nil
}

//Publish push messages to NATS
func (natsConn *NatsConn) Publish(scan *Scan) error {
	return nil
}
