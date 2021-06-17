package signer

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share/dkg"
)

func encodeJustificationBundle(jb *dkg.JustificationBundle) []byte {
	enc := NewEncoder()
	enc.WriteUint32(jb.DealerIndex)

	enc.WriteInt(len(jb.Justifications))
	for _, j := range jb.Justifications {
		enc.WriteUint32(j.ShareIndex)
		b, err := j.Share.MarshalBinary()
		if err != nil {
			panic(err)
		}
		enc.WriteFixedBytes(b)
	}

	enc.WriteFixedBytes(jb.SessionID)
	enc.WriteFixedBytes(jb.Signature)

	return enc.buf.Bytes()
}

func decodeJustificationBundle(b []byte) (*dkg.JustificationBundle, error) {
	jb := &dkg.JustificationBundle{}
	dec := NewDecoder(b)

	di, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	jb.DealerIndex = di

	jl, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	suite := bn256.NewSuiteG2()
	for ; jl > 0; jl-- {
		si, err := dec.ReadUint32()
		if err != nil {
			return nil, err
		}
		b, err := dec.ReadBytes()
		if err != nil {
			return nil, err
		}
		scalar := suite.Scalar().SetBytes(b)
		jb.Justifications = append(jb.Justifications, dkg.Justification{
			ShareIndex: si,
			Share:      scalar,
		})
	}

	sid, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	jb.SessionID = sid
	sig, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	jb.Signature = sig

	return jb, nil
}

func encodeResponseBundle(rb *dkg.ResponseBundle) []byte {
	enc := NewEncoder()
	enc.WriteUint32(rb.ShareIndex)

	enc.WriteInt(len(rb.Responses))
	for _, r := range rb.Responses {
		enc.WriteUint32(r.DealerIndex)
		enc.WriteBool(r.Status)
	}

	enc.WriteFixedBytes(rb.SessionID)
	enc.WriteFixedBytes(rb.Signature)

	return enc.buf.Bytes()
}

func decodeResponseBundle(b []byte) (*dkg.ResponseBundle, error) {
	rb := &dkg.ResponseBundle{}
	dec := NewDecoder(b)

	si, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	rb.ShareIndex = si

	rl, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	for ; rl > 0; rl-- {
		di, err := dec.ReadUint32()
		if err != nil {
			return nil, err
		}
		ss, err := dec.ReadBool()
		if err != nil {
			return nil, err
		}
		rb.Responses = append(rb.Responses, dkg.Response{
			DealerIndex: di,
			Status:      ss,
		})
	}

	sid, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	rb.SessionID = sid
	sig, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	rb.Signature = sig

	return rb, nil
}

func encodeDealBundle(db *dkg.DealBundle) []byte {
	enc := NewEncoder()
	enc.WriteUint32(db.DealerIndex)

	enc.WriteInt(len(db.Deals))
	for _, d := range db.Deals {
		enc.WriteUint32(d.ShareIndex)
		enc.WriteFixedBytes(d.EncryptedShare)
	}

	enc.WriteInt(len(db.Public))
	for _, p := range db.Public {
		b, err := p.MarshalBinary()
		if err != nil {
			panic(p)
		}
		enc.WriteFixedBytes(b)
	}

	enc.WriteFixedBytes(db.SessionID)
	enc.WriteFixedBytes(db.Signature)

	return enc.buf.Bytes()
}

func decodeDealBundle(b []byte) (*dkg.DealBundle, error) {
	db := &dkg.DealBundle{}
	dec := NewDecoder(b)

	di, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	db.DealerIndex = di

	dl, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	for ; dl > 0; dl-- {
		si, err := dec.ReadUint32()
		if err != nil {
			return nil, err
		}
		es, err := dec.ReadBytes()
		if err != nil {
			return nil, err
		}
		db.Deals = append(db.Deals, dkg.Deal{
			ShareIndex:     si,
			EncryptedShare: es,
		})
	}

	pl, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	suite := bn256.NewSuiteG2()
	for ; pl > 0; pl-- {
		pb, err := dec.ReadBytes()
		if err != nil {
			return nil, err
		}
		point := suite.G2().Point()
		err = point.UnmarshalBinary(pb)
		if err != nil {
			return nil, err
		}
		db.Public = append(db.Public, point)
	}

	sid, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	db.SessionID = sid
	sig, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	db.Signature = sig

	return db, nil
}

type Decoder struct {
	buf *bytes.Reader
}

func NewDecoder(b []byte) *Decoder {
	return &Decoder{buf: bytes.NewReader(b)}
}

func (dec *Decoder) Read(b []byte) error {
	l, err := dec.buf.Read(b)
	if err != nil {
		return err
	}
	if l != len(b) {
		return fmt.Errorf("data short %d %d", l, len(b))
	}
	return nil
}

func (dec *Decoder) ReadInt() (int, error) {
	d, err := dec.ReadUint32()
	return int(d), err
}

func (dec *Decoder) ReadUint32() (uint32, error) {
	var b [4]byte
	err := dec.Read(b[:])
	if err != nil {
		return 0, err
	}
	d := binary.BigEndian.Uint32(b[:])
	return d, nil
}

func (dec *Decoder) ReadUint64() (uint64, error) {
	var b [8]byte
	err := dec.Read(b[:])
	if err != nil {
		return 0, err
	}
	d := binary.BigEndian.Uint64(b[:])
	return d, nil
}

func (dec *Decoder) ReadBytes() ([]byte, error) {
	l, err := dec.ReadInt()
	if err != nil {
		return nil, err
	}
	if l == 0 {
		return nil, nil
	}
	b := make([]byte, l)
	err = dec.Read(b)
	return b, err
}

func (dec *Decoder) ReadBool() (bool, error) {
	b, err := dec.buf.ReadByte()
	return b == 1, err
}

type Encoder struct {
	buf *bytes.Buffer
}

func NewEncoder() *Encoder {
	return &Encoder{buf: new(bytes.Buffer)}
}

func (enc *Encoder) Write(b []byte) {
	l, err := enc.buf.Write(b)
	if err != nil {
		panic(err)
	}
	if l != len(b) {
		panic(b)
	}
}

func (enc *Encoder) WriteFixedBytes(b []byte) {
	enc.WriteInt(len(b))
	enc.Write(b)
}

func (enc *Encoder) WriteInt(d int) {
	enc.WriteUint32(uint32(d))
}

func (enc *Encoder) WriteUint32(d uint32) {
	b := uint32ToBytes(d)
	enc.Write(b)
}

func (enc *Encoder) WriteBool(b bool) {
	if b {
		enc.buf.WriteByte(1)
	} else {
		enc.buf.WriteByte(0)
	}
}

func uint32ToBytes(d uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, d)
	return b
}
