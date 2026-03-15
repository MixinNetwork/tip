package signer

import (
	"context"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/stretchr/testify/require"
)

func signerTestScalar() kyber.Scalar {
	return bn256.NewSuiteG2().Scalar().Pick(random.New())
}

func TestSetupBundleRoundTrip(t *testing.T) {
	require := require.New(t)

	want := &SetupBundle{
		Nonce:     42,
		Timestamp: time.Unix(1700000000, 456),
	}

	decoded, err := decodeSetupBundle(encodeSetupBundle(want))
	require.NoError(err)
	require.Equal(want.Nonce, decoded.Nonce)
	require.True(want.Timestamp.Equal(decoded.Timestamp))

	_, err = decodeSetupBundle([]byte{1, 2, 3})
	require.Error(err)
}

func TestMakeSetupMessageProducesVerifiableMessage(t *testing.T) {
	require := require.New(t)

	key := signerTestScalar()
	pub := crypto.PublicKey(key)
	node := &Node{
		signers: []dkg.Node{
			{Index: 0, Public: pub},
			{Index: 1, Public: crypto.PublicKey(signerTestScalar())},
		},
	}

	msg, err := decodeMessage(MakeSetupMessage(context.Background(), key, 99))
	require.NoError(err)
	require.Equal(MessageActionSetup, msg.Action)
	require.Equal(crypto.PublicKeyString(pub), msg.Sender)
	require.NoError(node.verifyMessage(msg))

	sb, err := decodeSetupBundle(msg.Data)
	require.NoError(err)
	require.Equal(uint64(99), sb.Nonce)
	require.WithinDuration(time.Now(), sb.Timestamp, 2*time.Second)
}

func TestVerifyMessageRejectsUnauthorizedOrTamperedMessages(t *testing.T) {
	require := require.New(t)

	key := signerTestScalar()
	pub := crypto.PublicKey(key)
	msg, err := decodeMessage(MakeSetupMessage(context.Background(), key, 7))
	require.NoError(err)

	authorized := &Node{signers: []dkg.Node{{Index: 0, Public: pub}}}
	require.NoError(authorized.verifyMessage(msg))

	tampered := *msg
	tampered.Data = append([]byte(nil), msg.Data...)
	tampered.Data[0] ^= 0xff
	require.Error(authorized.verifyMessage(&tampered))

	unauthorized := &Node{signers: []dkg.Node{{Index: 1, Public: crypto.PublicKey(signerTestScalar())}}}
	err = unauthorized.verifyMessage(msg)
	require.Error(err)
	require.Contains(err.Error(), "unauthorized sender")
}

func TestDealBundleRoundTrip(t *testing.T) {
	require := require.New(t)

	db := &dkg.DealBundle{
		DealerIndex: 5,
		Deals: []dkg.Deal{
			{ShareIndex: 1, EncryptedShare: []byte("share-1")},
			{ShareIndex: 2, EncryptedShare: []byte("share-2")},
		},
		Public: []kyber.Point{
			crypto.PublicKey(signerTestScalar()),
			crypto.PublicKey(signerTestScalar()),
		},
		SessionID: []byte("session"),
		Signature: []byte("signature"),
	}

	nonce, decoded, err := decodeDealBundle(encodeDealBundle(db, 123))
	require.NoError(err)
	require.Equal(uint64(123), nonce)
	require.Equal(db.DealerIndex, decoded.DealerIndex)
	require.Equal(db.Deals, decoded.Deals)
	require.Equal(db.SessionID, decoded.SessionID)
	require.Equal(db.Signature, decoded.Signature)
	require.Len(decoded.Public, len(db.Public))
	for i := range db.Public {
		require.True(decoded.Public[i].Equal(db.Public[i]))
	}
}

func TestDecodeDealBundleRejectsInvalidPublicKey(t *testing.T) {
	require := require.New(t)

	enc := NewEncoder()
	enc.WriteUint64(9)
	enc.WriteUint32(1)
	enc.WriteInt(0)
	enc.WriteInt(1)
	enc.WriteFixedBytes([]byte{1, 2, 3})
	enc.WriteFixedBytes([]byte("session"))
	enc.WriteFixedBytes([]byte("signature"))

	_, _, err := decodeDealBundle(enc.buf.Bytes())
	require.Error(err)
}

func TestResponseAndJustificationBundleRoundTrip(t *testing.T) {
	require := require.New(t)

	rb := &dkg.ResponseBundle{
		ShareIndex: 3,
		Responses: []dkg.Response{
			{DealerIndex: 1, Status: true},
			{DealerIndex: 2, Status: false},
		},
		SessionID: []byte("session"),
		Signature: []byte("signature"),
	}
	decodedResponses, err := decodeResponseBundle(encodeResponseBundle(rb))
	require.NoError(err)
	require.Equal(rb.ShareIndex, decodedResponses.ShareIndex)
	require.Equal(rb.Responses, decodedResponses.Responses)
	require.Equal(rb.SessionID, decodedResponses.SessionID)
	require.Equal(rb.Signature, decodedResponses.Signature)

	jb := &dkg.JustificationBundle{
		DealerIndex: 8,
		Justifications: []dkg.Justification{
			{ShareIndex: 1, Share: signerTestScalar()},
			{ShareIndex: 2, Share: signerTestScalar()},
		},
		SessionID: []byte("session"),
		Signature: []byte("signature"),
	}
	decodedJustifications, err := decodeJustificationBundle(encodeJustificationBundle(jb))
	require.NoError(err)
	require.Equal(jb.DealerIndex, decodedJustifications.DealerIndex)
	require.Equal(jb.SessionID, decodedJustifications.SessionID)
	require.Equal(jb.Signature, decodedJustifications.Signature)
	require.Len(decodedJustifications.Justifications, len(jb.Justifications))
	for i := range jb.Justifications {
		require.Equal(jb.Justifications[i].ShareIndex, decodedJustifications.Justifications[i].ShareIndex)
		require.Equal(
			crypto.PrivateKeyBytes(jb.Justifications[i].Share),
			crypto.PrivateKeyBytes(decodedJustifications.Justifications[i].Share),
		)
	}
}

func TestDecoderPrimitives(t *testing.T) {
	require := require.New(t)

	enc := NewEncoder()
	enc.WriteInt(0)
	enc.WriteBool(true)
	enc.WriteBool(false)
	enc.WriteUint32(7)
	enc.WriteUint64(11)

	dec := NewDecoder(enc.buf.Bytes())
	b, err := dec.ReadBytes()
	require.NoError(err)
	require.Nil(b)

	v, err := dec.ReadBool()
	require.NoError(err)
	require.True(v)

	v, err = dec.ReadBool()
	require.NoError(err)
	require.False(v)

	u32, err := dec.ReadUint32()
	require.NoError(err)
	require.Equal(uint32(7), u32)

	u64, err := dec.ReadUint64()
	require.NoError(err)
	require.Equal(uint64(11), u64)

	var buf [4]byte
	err = NewDecoder([]byte{1, 2}).Read(buf[:])
	require.Error(err)
}
