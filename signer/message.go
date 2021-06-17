package signer

import (
	"context"
	"math"
	"time"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/sign/bls"
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
	Data      []byte
	Signature []byte
}

type SetupBundle struct {
	Nonce     uint64
	Timestamp time.Time
}

func encodeSetupBundle(sb *SetupBundle) []byte {
	enc := NewEncoder()
	enc.WriteUint64(sb.Nonce)
	enc.WriteUint64(uint64(sb.Timestamp.UnixNano()))
	return enc.buf.Bytes()
}

func decodeSetupBundle(b []byte) (*SetupBundle, error) {
	sb := &SetupBundle{}
	dec := NewDecoder(b)

	no, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	sb.Nonce = no

	ts, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	sb.Timestamp = time.Unix(0, int64(ts))
	return sb, nil
}

func MakeSetupMessage(ctx context.Context, key kyber.Scalar, nonce uint64) []byte {
	data := encodeSetupBundle(&SetupBundle{
		Nonce:     nonce,
		Timestamp: time.Now(),
	})
	return makeMessage(key, MessageActionSetup, data)
}

func (node *Node) handleSetupMessage(ctx context.Context, msg *Message) error {
	sb, err := decodeSetupBundle(msg.Data)
	if err != nil {
		return err
	}
	var expired []string
	for k, v := range node.setupActions {
		if sb.Nonce < v.Nonce {
			return nil
		}
		if math.Abs(sb.Timestamp.Sub(v.Timestamp).Seconds()) > 300 {
			return nil
		}
		if sb.Nonce > v.Nonce {
			expired = append(expired, k)
		}
	}
	for _, k := range expired {
		delete(node.setupActions, k)
	}
	node.setupActions[msg.Sender] = sb
	if len(node.setupActions) >= node.Threshold() {
		go node.Setup(ctx, sb.Nonce)
	}
	return nil
}

func makeMessage(key kyber.Scalar, action int, data []byte) []byte {
	point := PublicKey(key)
	msg := &Message{
		Action: action,
		Sender: PublicKeyString(point),
		Data:   data,
	}
	b := encodeMessage(msg)
	suite := bn256.NewSuiteG2()
	scheme := bls.NewSchemeOnG1(suite)
	sig, err := scheme.Sign(key, b)
	if err != nil {
		panic(err)
	}
	msg.Signature = sig
	return encodeMessage(msg)
}

func encodeMessage(m *Message) []byte {
	enc := NewEncoder()
	enc.WriteInt(m.Action)
	enc.WriteFixedBytes([]byte(m.Sender))
	enc.WriteFixedBytes(m.Data)
	enc.WriteFixedBytes(m.Signature)
	return enc.buf.Bytes()
}

func decodeMessage(b []byte) (*Message, error) {
	msg := &Message{}
	dec := NewDecoder(b)

	an, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	msg.Action = an

	sender, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	msg.Sender = string(sender)

	data, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	msg.Data = data

	sig, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	msg.Signature = sig

	return msg, nil
}
