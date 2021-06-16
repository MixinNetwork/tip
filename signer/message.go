package signer

import (
	"math"
	"time"
)

const (
	MessageActionSetup       = 7000
	MessageActionDKGDeal     = 7001
	MessageActionDKGResponse = 7002
	MessageActionDKGJustify  = 7003

	MessageSetupPeriodSeconds = 300
)

type Message struct {
	Action    int
	Sender    string
	Nonce     uint64
	Timestamp time.Time
	Signature []byte
}

func parseMessage(b []byte) (*Message, error) {
	return nil, nil
}

func (node *Node) handleSetupMessage(msg *Message) error {
	var expired []string
	for _, v := range node.setupActions {
		if msg.Nonce < v.Nonce {
			return nil
		}
		if math.Abs(msg.Timestamp.Sub(v.Timestamp).Seconds()) > 300 {
			return nil
		}
		if msg.Nonce > v.Nonce {
			expired = append(expired, v.Sender)
		}
	}
	for _, k := range expired {
		delete(node.setupActions, k)
	}
	node.setupActions[msg.Sender] = msg
	if len(node.setupActions) >= node.Threshold() {
		return node.Setup()
	}
	return nil
}
