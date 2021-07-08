package main

//MessageBus Interface for making generic connections to message busses
type MessageBus interface {
	Connect(host, port string, errChan chan error)
	Subscribe(errChan chan error) chan *Message
	Publish(run *Run) error
	Close()
}

type Message struct {
	Data        []byte
	acknowledge chan bool
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
