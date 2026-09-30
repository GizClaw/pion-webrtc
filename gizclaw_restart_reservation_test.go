// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/pion/datachannel"
	"github.com/pion/sctp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func closedRestartReservation(t *testing.T, pair *restartTestPair, remote bool) (*DataChannel, weak.Pointer[sctp.Stream]) {
	t.Helper()
	var channel *DataChannel
	var peerChannel *datachannel.DataChannel
	if remote {
		incoming := make(chan *DataChannel, 1)
		pair.transport.OnDataChannel(func(channel *DataChannel) { incoming <- channel })
		var err error
		peerChannel, err = datachannel.Dial(pair.peer, 0, &datachannel.Config{
			ChannelType: datachannel.ChannelTypeReliable, LoggerFactory: pair.transport.api.settingEngine.LoggerFactory,
		})
		require.NoError(t, err)
		select {
		case channel = <-incoming:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "incoming DCEP channel was not announced")
		}
		require.Eventually(t, func() bool { return channel.ReadyState() == DataChannelStateOpen }, 5*time.Second, time.Millisecond)
	} else {
		channel, peerChannel = pair.openLocal(t, 0)
	}
	stream := restartReservation(t, pair.transport, channel).stream
	detached, err := channel.Detach()
	require.NoError(t, err)
	require.NoError(t, detached.Close())
	require.NoError(t, peerChannel.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, _, err = peerChannel.ReadDataChannel(make([]byte, 64))
	require.ErrorIs(t, err, io.EOF)
	require.Eventually(t, func() bool { return stream.Value().State() == sctp.StreamStateClosed }, 5*time.Second, time.Millisecond)

	return channel, stream
}

func TestGizclawRestartReservationResetFIFO(t *testing.T) {
	for _, testCase := range []struct {
		name                         string
		collect, failBinding, remote bool
	}{
		{name: "local"},
		{name: "collected detached", collect: true},
		{name: "failed binding cleanup", failBinding: true},
		{name: "remote then local", remote: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			pair := newRestartTestPair(t)
			transport := pair.transport
			entered := make(chan uint16, 1)
			// Defer the transport consumer while letting SCTP finish its callback,
			// so completed-stream objects can be collected before notification delivery.
			pair.association.OnStreamResetComplete(func(id uint16) { entered <- id })
			old, oldStream := closedRestartReservation(t, pair, testCase.remote)
			oldOwner := weak.Make(old)
			select {
			case id := <-entered:
				require.Equal(t, uint16(0), id)
			case <-time.After(5 * time.Second):
				require.FailNow(t, "old reset callback was not reached")
			}
			if testCase.collect {
				old = nil
				require.Eventually(t, func() bool {
					runtime.GC()

					return oldOwner.Value() == nil && oldStream.Value() == nil
				}, 5*time.Second, 20*time.Millisecond)
			}
			// SCTP has removed the old Stream, while its SID-only reset notification
			// is paused. A new binding and local classifier can already be registered.
			id := uint16(0)
			fresh, err := transport.api.NewDataChannel(transport, &DataChannelParameters{ID: &id, Ordered: true})
			require.NoError(t, err)
			freshReservation := restartReservation(t, transport, fresh)
			require.Equal(t, uint32(2), restartIDCount(transport, 0))
			require.NotEqual(t, oldOwner, weak.Make(fresh))
			if testCase.failBinding {
				require.ErrorIs(t, transport.bindDataChannel(old, pair.association, oldStream.Value()), io.ErrClosedPipe)
				require.Equal(t, uint32(1), restartIDCount(transport, 0))
				transport.discardFailedDataChannel(old)
				transport.discardFailedDataChannel(old)
				require.Equal(t, uint32(1), restartIDCount(transport, 0), "failed-open cleanup is idempotent for that owner")
			}
			transport.onStreamResetComplete(pair.association, 0)
			require.Equal(t, uint32(1), restartIDCount(transport, 0))
			assert.Equal(t, freshReservation, restartReservation(t, transport, fresh))
			transport.lock.RLock()
			assert.Len(t, transport.dataChannelResetReservations[0], 1)
			assert.Same(t, freshReservation.resetReservation, transport.dataChannelResetReservations[0][0])
			assert.Len(t, transport.localDataChannelGenerations[0], 1)
			assert.Same(t, freshReservation.resetReservation, transport.localDataChannelGenerations[0][0].resetReservation,
				"the old local or remote reset must not consume the new SID classifier")
			transport.lock.RUnlock()
			// Complete the new real DCEP handshake after the old reset observer resumes.
			accepted := make(chan error, 1)
			go func() {
				_, acceptErr := datachannel.Accept(pair.peer, &datachannel.Config{LoggerFactory: transport.api.settingEngine.LoggerFactory})
				accepted <- acceptErr
			}()
			select {
			case acceptErr := <-accepted:
				require.NoError(t, acceptErr)
			case <-time.After(5 * time.Second):
				require.FailNow(t, "new DCEP channel did not complete")
			}
			runtime.KeepAlive(fresh)
			runtime.KeepAlive(old)
		})
	}
}

func TestGizclawRestartDiscardsDetachedLocalClassifier(t *testing.T) {
	pair := newRestartTestPair(t)
	transport := pair.transport
	old, _ := pair.openLocal(t, 0)
	retained, _ := pair.openLocal(t, 2)
	retainedToken := restartReservation(t, transport, retained).resetReservation
	pair.conn.dropResets.Store(true)
	detached, err := old.Detach()
	require.NoError(t, err)
	require.NoError(t, detached.Close())
	require.Eventually(t, func() bool { return pair.conn.resetDrops.Load() != 0 }, 5*time.Second, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	replacement, err := pair.restart(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = replacement.Close() })
	transport.lock.RLock()
	assert.Empty(t, transport.localDataChannelGenerations[0])
	assert.Empty(t, transport.dataChannelResetReservations[0])
	assert.Same(t, retainedToken, transport.localDataChannelGenerations[2][0].resetReservation)
	assert.Equal(t, uint64(1), retainedToken.generation)
	transport.lock.RUnlock()
	// The new remote OPEN reuses the discarded local SID. It must pass through
	// the SID FIFO classifier and be announced as a new incoming channel.
	incoming := make(chan *DataChannel, 1)
	transport.OnDataChannel(func(channel *DataChannel) { incoming <- channel })
	peerChannel, err := datachannel.Dial(replacement, 0, &datachannel.Config{
		ChannelType: datachannel.ChannelTypeReliable, LoggerFactory: transport.api.settingEngine.LoggerFactory,
	})
	require.NoError(t, err)
	var fresh *DataChannel
	select {
	case fresh = <-incoming:
	case <-ctx.Done():
		require.FailNow(t, "discarded local generation swallowed the new remote DCEP OPEN")
	}
	require.Eventually(t, func() bool { return fresh.ReadyState() == DataChannelStateOpen }, 5*time.Second, time.Millisecond)
	reader, err := fresh.DetachWithDeadline()
	require.NoError(t, err)
	require.NoError(t, reader.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = peerChannel.WriteDataChannel([]byte("new remote generation"), false)
	require.NoError(t, err)
	buffer := make([]byte, 64)
	n, _, err := reader.ReadDataChannel(buffer)
	require.NoError(t, err)
	assert.Equal(t, "new remote generation", string(buffer[:n]))
	assert.False(t, transport.acceptLocalDataChannelGeneration(0))
	assert.Equal(t, uint32(1), restartIDCount(transport, 0))
	runtime.KeepAlive(old)
	runtime.KeepAlive(retained)
	runtime.KeepAlive(fresh)
}

func TestGizclawRestartFailedOpenReusesOpenStream(t *testing.T) {
	for _, existingOwner := range []bool{false, true} {
		name := "reuse after failure"
		if existingOwner {
			name = "failure alongside existing owner"
		}
		t.Run(name, func(t *testing.T) {
			pair := newRestartTestPair(t)
			transport := pair.transport
			id := uint16(0)
			var fresh *DataChannel
			var peerChannel *datachannel.DataChannel
			if existingOwner {
				fresh, peerChannel = pair.openLocal(t, id)
			}
			baseline := restartIDCount(transport, id)
			_, err := transport.api.NewDataChannel(transport, &DataChannelParameters{
				ID: &id, Ordered: true, Protocol: strings.Repeat("x", 1<<16),
			})
			require.ErrorIs(t, err, datachannel.ErrTooLongProtocol)
			stream, err := pair.association.OpenStream(id, sctp.PayloadTypeWebRTCBinary)
			require.NoError(t, err)
			require.Equal(t, sctp.StreamStateOpen, stream.State(), "abandoning a failed open has not requested a reset")
			require.Equal(t, baseline, restartIDCount(transport, id))

			// A successful DCEP channel uses this exact still-open SCTP Stream. Only
			// its eventual close will produce a real reset notification.
			if !existingOwner {
				fresh, peerChannel = pair.openLocal(t, id)
			}
			require.Same(t, stream, restartReservation(t, transport, fresh).stream.Value())
			var resets atomic.Uint32
			pair.association.OnStreamResetComplete(func(streamID uint16) {
				transport.onStreamResetComplete(pair.association, streamID)
				resets.Add(1)
			})
			require.NoError(t, fresh.Close())
			require.NoError(t, peerChannel.SetReadDeadline(time.Now().Add(5*time.Second)))
			_, _, err = peerChannel.ReadDataChannel(make([]byte, 64))
			require.ErrorIs(t, err, io.EOF)
			require.Eventually(t, func() bool { return resets.Load() == 1 }, 5*time.Second, time.Millisecond)
			assert.Equal(t, uint32(0), restartIDCount(transport, id), "the single reset must release the successful owner's ID")
			transport.lock.RLock()
			assert.Empty(t, transport.dataChannelReservations)
			assert.Empty(t, transport.dataChannelResetReservations)
			assert.Empty(t, transport.localDataChannelGenerations)
			transport.lock.RUnlock()
			runtime.KeepAlive(fresh)
		})
	}
}
