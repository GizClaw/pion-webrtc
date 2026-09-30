// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
	"weak"

	"github.com/pion/datachannel"
	"github.com/pion/logging"
	"github.com/pion/sctp"
	"github.com/pion/webrtc/v4/pkg/rtcerr"
)

const sctpMaxChannels = uint16(65535)

type dataChannelReservation struct {
	id               uint16
	association      weak.Pointer[sctp.Association]
	stream           weak.Pointer[sctp.Stream]
	generation       uint64
	resetReservation *dataChannelResetReservation
}

// The FIFO remains after a failed open releases its ID, so a delayed reset
// notification consumes that old stream's token rather than a newer owner.
type dataChannelResetReservation struct {
	owner       weak.Pointer[DataChannel]
	association weak.Pointer[sctp.Association]
	stream      weak.Pointer[sctp.Stream]
	generation  uint64
}

// defaultSCTPDataChannelOpenTimeout bounds how long an accepted SCTP stream may
// wait for its DCEP DATA_CHANNEL_OPEN before the stream is closed.
const defaultSCTPDataChannelOpenTimeout = 10 * time.Second

func newSCTPTransportMetadata(metadata sctp.AssociationMetadata) SCTPTransportMetadata {
	partialReliabilityMode := SCTPTransportPartialReliabilityModeNone
	switch metadata.PartialReliabilityMode {
	case sctp.PartialReliabilityModeForwardTSN:
		partialReliabilityMode = SCTPTransportPartialReliabilityModeForwardTSN
	case sctp.PartialReliabilityModeIForwardTSN:
		partialReliabilityMode = SCTPTransportPartialReliabilityModeIForwardTSN
	case sctp.PartialReliabilityModeNone:
		partialReliabilityMode = SCTPTransportPartialReliabilityModeNone
	}

	return SCTPTransportMetadata{
		MessageInterleavingEnabled:   metadata.MessageInterleavingEnabled,
		PartialReliabilityMode:       partialReliabilityMode,
		ZeroChecksumSendingEnabled:   metadata.ZeroChecksumSendingEnabled,
		ZeroChecksumReceivingEnabled: metadata.ZeroChecksumReceivingEnabled,
		NumInboundStreams:            metadata.NumInboundStreams,
		NumOutboundStreams:           metadata.NumOutboundStreams,
	}
}

// SCTPTransport provides details about the SCTP transport.
type SCTPTransport struct {
	lock sync.RWMutex

	dtlsTransport *DTLSTransport

	// State represents the current state of the SCTP transport.
	state SCTPTransportState

	// SCTPTransportState doesn't have an enum to distinguish between New/Connecting
	// so we need a dedicated field
	isStarted bool

	// MaxChannels represents the maximum amount of DataChannel's that can
	// be used simultaneously.
	maxChannels *uint16

	// OnStateChange  func()

	onErrorHandler func(error)
	onCloseHandler func(error)

	sctpAssociation            *sctp.Association
	onDataChannelHandler       func(*DataChannel)
	onDataChannelOpenedHandler func(*DataChannel)

	// DataChannels
	dataChannels []*DataChannel
	// Count reservations because a reused stream can arrive before the old
	// generation's reset-complete callback runs on this association.
	dataChannelIDsUsed           map[uint16]uint32
	dataChannelReservations      map[weak.Pointer[DataChannel]]dataChannelReservation
	dataChannelResetReservations map[uint16][]*dataChannelResetReservation
	associationGeneration        uint64
	// Advance allocations within the negotiated DTLS-role parity instead of
	// immediately selecting the lowest released ID again. Reset completion is
	// still the reuse boundary, while spreading successive short-lived channels
	// across the available stream space avoids coupling every new generation to
	// the immediately preceding reset exchange.
	nextDataChannelID uint16
	// Detach removes DataChannels from dataChannels before their ACK can arrive.
	// Keep each locally opened stream generation classified independently from
	// that garbage-collection list until its reset completes. SCTP may recreate
	// the Go Stream object for the same ID while completing a reset, so identity
	// here must be the ordered generation, not a Stream pointer.
	localDataChannelGenerations map[uint16][]*localDataChannelGeneration
	dataChannelsOpened          uint32
	dataChannelsRequested       uint32
	dataChannelsAccepted        uint32

	localSctpInit []byte

	api *API
	log logging.LeveledLogger
}

// NewSCTPTransport creates a new SCTPTransport.
// This constructor is part of the ORTC API. It is not
// meant to be used together with the basic WebRTC API.
func (api *API) NewSCTPTransport(dtls *DTLSTransport) *SCTPTransport {
	res := &SCTPTransport{
		dtlsTransport:                dtls,
		state:                        SCTPTransportStateConnecting,
		api:                          api,
		log:                          api.settingEngine.LoggerFactory.NewLogger("ortc"),
		dataChannelIDsUsed:           make(map[uint16]uint32),
		dataChannelReservations:      make(map[weak.Pointer[DataChannel]]dataChannelReservation),
		dataChannelResetReservations: make(map[uint16][]*dataChannelResetReservation),
		localDataChannelGenerations:  make(map[uint16][]*localDataChannelGeneration),
	}

	res.updateMaxChannels()

	return res
}

// Transport returns the DTLSTransport instance the SCTPTransport is sending over.
func (r *SCTPTransport) Transport() *DTLSTransport {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.dtlsTransport
}

// GetCapabilities returns the SCTPCapabilities of the SCTPTransport.
func (r *SCTPTransport) GetCapabilities() SCTPCapabilities {
	var maxMessageSize uint32
	if a := r.association(); a != nil {
		maxMessageSize = a.MaxMessageSize()
	}

	return SCTPCapabilities{
		MaxMessageSize: maxMessageSize,
	}
}

// Start the SCTPTransport. Since both local and remote parties must mutually
// create an SCTPTransport, SCTP SO (Simultaneous Open) is used to establish
// a connection over SCTP.
func (r *SCTPTransport) Start(capabilities SCTPCapabilities) error {
	return r.StartContext(context.Background(), capabilities)
}

// StartContext starts the SCTP transport using the remote capabilities.
// The context controls SCTP association establishment only. Canceling it after
// establishment does not close the association. Cancellation returns the context
// error. If an association is being established, its underlying DTLS connection is
// closed in the background. A failed association setup leaves the transport closed.
// An already-canceled context leaves the transport and DTLS connection unchanged.
//
//nolint:cyclop
func (r *SCTPTransport) StartContext(ctx context.Context, capabilities SCTPCapabilities) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if r.isStarted {
		return nil
	}
	r.isStarted = true

	maxMessageSize := capabilities.MaxMessageSize
	if maxMessageSize == 0 {
		maxMessageSize = sctpMaxMessageSizeUnsetValue
	}
	remoteSctpInit := []byte(capabilities.sctpInit)

	dtlsTransport := r.Transport()
	if dtlsTransport == nil || dtlsTransport.conn == nil {
		return errSCTPTransportDTLS
	}
	opts := r.sctpClientOptions(dtlsTransport.conn, maxMessageSize)
	if len(r.localSctpInit) > 0 && len(remoteSctpInit) > 0 {
		opts = append(
			opts,
			sctp.WithSNAP(r.localSctpInit, remoteSctpInit),
		)
	}
	sctpAssociation, err := sctp.ClientContext(ctx, opts...)
	if err != nil {
		r.lock.Lock()
		r.state = SCTPTransportStateClosed
		r.lock.Unlock()

		return err
	}
	r.setAssociation(sctpAssociation)
	r.lock.RLock()
	dataChannels := append([]*DataChannel{}, r.dataChannels...)
	r.lock.RUnlock()

	var openedDCCount uint32
	for _, d := range dataChannels {
		if d.ReadyState() == DataChannelStateConnecting {
			err := d.open(r)
			if err != nil {
				r.discardFailedDataChannel(d)
				r.log.Warnf("failed to open data channel: %s", err)

				continue
			}
			openedDCCount++
		}
	}

	r.lock.Lock()
	r.dataChannelsOpened += openedDCCount
	r.lock.Unlock()

	go r.acceptDataChannels(sctpAssociation)

	return nil
}

func (r *SCTPTransport) sctpClientOptions(netConn net.Conn, maxMessageSize uint32) []sctp.ClientOption {
	opts := []sctp.ClientOption{
		sctp.WithNetConn(netConn),
		sctp.WithLoggerFactory(r.api.settingEngine.LoggerFactory),
		sctp.WithMTU(sctpOutboundMTU),
		sctp.WithMaxMessageSize(maxMessageSize),
		// A closed DataChannel discards the messages it receives, so they
		// must not hold the association's receive window either.
		sctp.WithDiscardInboundAfterClose(true),
	}

	return append(opts, r.optionalSCTPClientOptions()...)
}

func (r *SCTPTransport) optionalSCTPClientOptions() []sctp.ClientOption {
	opts := make([]sctp.ClientOption, 0, 9)

	if r.api.settingEngine.sctp.maxReceiveBufferSize != 0 {
		opts = append(opts, sctp.WithMaxReceiveBufferSize(r.api.settingEngine.sctp.maxReceiveBufferSize))
	}

	if r.api.settingEngine.sctp.numInboundStreams != 0 || r.api.settingEngine.sctp.numOutboundStreams != 0 {
		opts = append(opts, sctp.WithNumStreams(
			r.api.settingEngine.sctp.numInboundStreams,
			r.api.settingEngine.sctp.numOutboundStreams,
		))
	}

	if r.api.settingEngine.sctp.enableZeroChecksum {
		opts = append(opts, sctp.WithEnableZeroChecksum(true))
	}

	if r.api.settingEngine.detach.DataChannels && r.api.settingEngine.dataChannelBlockWrite {
		opts = append(opts, sctp.WithBlockWrite(true))
	}

	if r.api.settingEngine.sctp.rtoMax > 0 {
		opts = append(
			opts,
			sctp.WithRTOMax(float64(r.api.settingEngine.sctp.rtoMax)/float64(time.Millisecond)),
		)
	}

	if r.api.settingEngine.sctp.handshakeRTOMax > 0 {
		opts = append(
			opts,
			sctp.WithHandshakeRTOMax(
				float64(r.api.settingEngine.sctp.handshakeRTOMax)/float64(time.Millisecond),
			),
		)
	}

	if r.api.settingEngine.sctp.minCwnd != 0 {
		opts = append(opts, sctp.WithMinCwnd(r.api.settingEngine.sctp.minCwnd))
	}

	if r.api.settingEngine.sctp.fastRtxWnd != 0 {
		opts = append(opts, sctp.WithFastRtxWnd(r.api.settingEngine.sctp.fastRtxWnd))
	}

	if r.api.settingEngine.sctp.cwndCAStep != 0 {
		opts = append(opts, sctp.WithCwndCAStep(r.api.settingEngine.sctp.cwndCAStep))
	}

	return opts
}

// Stop stops the SCTPTransport.
func (r *SCTPTransport) Stop() error {
	r.lock.Lock()
	association := r.sctpAssociation
	if association == nil {
		r.lock.Unlock()

		return nil
	}
	r.sctpAssociation = nil
	r.state = SCTPTransportStateClosed
	r.lock.Unlock()

	association.OnStreamResetComplete(nil)
	association.OnAssociationRestart(nil)
	association.Abort("")

	return nil
}

// acceptDataChannels accepts incoming SCTP streams and opens a DataChannel
// for each of them. It only returns when the association stops producing
// streams; a failure on a single stream never ends the loop.
func (r *SCTPTransport) acceptDataChannels(
	assoc *sctp.Association,
) {
	for {
		// check if the association has been stopped before calling accept.
		if !r.isCurrentAssociation(assoc) {
			r.onClose(nil)

			return
		}

		stream, err := assoc.AcceptStream()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				r.log.Errorf("Failed to accept data channel: %v", err)
				r.onError(err)
				r.onClose(err)
			} else {
				r.onClose(nil)
			}

			return
		}

		stream.SetDefaultPayloadType(sctp.PayloadTypeWebRTCBinary)
		// Classify against the live local DataChannel registry rather than a
		// startup snapshot: applications may create local DataChannels after
		// the association has started, and the first inbound packet on those
		// streams is a DataChannelAck, not a new Open.
		if r.acceptLocalDataChannelGeneration(stream.StreamIdentifier()) {
			continue
		}

		// Wait for the DCEP OPEN off the accept loop, so a stream whose OPEN is
		// delayed or lost cannot block every stream accepted after it.
		go r.openAcceptedDataChannel(assoc, stream)
	}
}

type localDataChannelGeneration struct {
	accepted         bool
	resetReservation *dataChannelResetReservation
}

func (r *SCTPTransport) registerLocalDataChannelGeneration(streamID uint16, reservation *dataChannelResetReservation) *localDataChannelGeneration {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.registerLocalDataChannelGenerationLocked(streamID, reservation)
}

// The caller must hold r.lock.
func (r *SCTPTransport) registerLocalDataChannelGenerationLocked(streamID uint16, reservation *dataChannelResetReservation) *localDataChannelGeneration {
	if r.localDataChannelGenerations == nil {
		r.localDataChannelGenerations = make(map[uint16][]*localDataChannelGeneration)
	}
	generation := &localDataChannelGeneration{resetReservation: reservation}
	r.localDataChannelGenerations[streamID] = append(r.localDataChannelGenerations[streamID], generation)
	return generation
}

func (r *SCTPTransport) bindLocalDataChannel(channel *DataChannel, association *sctp.Association, stream *sctp.Stream) (*localDataChannelGeneration, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if err := r.bindDataChannelLocked(channel, association, stream); err != nil {
		return nil, err
	}
	reservation := r.dataChannelReservations[weak.Make(channel)]

	return r.registerLocalDataChannelGenerationLocked(reservation.id, reservation.resetReservation), nil
}

// The caller must hold r.lock. Match the generation token, not just the SID.
func (r *SCTPTransport) discardLocalDataChannelGenerationLocked(streamID uint16, reservation *dataChannelResetReservation) {
	generations := r.localDataChannelGenerations[streamID]
	for i := 0; i < len(generations); {
		if generations[i].resetReservation != reservation {
			i++

			continue
		}
		copy(generations[i:], generations[i+1:])
		generations[len(generations)-1] = nil
		generations = generations[:len(generations)-1]
	}
	if len(generations) == 0 {
		delete(r.localDataChannelGenerations, streamID)
	} else {
		r.localDataChannelGenerations[streamID] = generations
	}
}

func (r *SCTPTransport) acceptLocalDataChannelGeneration(streamID uint16) bool {
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, generation := range r.localDataChannelGenerations[streamID] {
		if !generation.accepted {
			generation.accepted = true

			return true
		}
	}

	return false
}

func (r *SCTPTransport) unregisterLocalDataChannelGeneration(
	streamID uint16,
	generation *localDataChannelGeneration,
) {
	r.lock.Lock()
	defer r.lock.Unlock()

	generations := r.localDataChannelGenerations[streamID]
	for i := range generations {
		if generations[i] != generation {
			continue
		}
		generations = append(generations[:i], generations[i+1:]...)
		if len(generations) == 0 {
			delete(r.localDataChannelGenerations, streamID)
		} else {
			r.localDataChannelGenerations[streamID] = generations
		}

		return
	}
}

// openAcceptedDataChannel waits, bounded by the DataChannel open timeout, for
// the DCEP OPEN on an accepted stream and then announces the DataChannel.
// Any failure closes just this stream.
//
//nolint:cyclop
func (r *SCTPTransport) openAcceptedDataChannel(assoc *sctp.Association, stream *sctp.Stream) {
	sid := stream.StreamIdentifier()

	timeout := r.api.settingEngine.sctp.dataChannelOpenTimeout
	if timeout <= 0 {
		timeout = defaultSCTPDataChannelOpenTimeout
	}

	dc, err := func() (*datachannel.DataChannel, error) {
		if err := stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}

		dc, err := datachannel.Server(stream, &datachannel.Config{
			LoggerFactory: r.api.settingEngine.LoggerFactory,
		})
		if err != nil {
			return nil, err
		}

		return dc, stream.SetReadDeadline(time.Time{})
	}()
	if err != nil {
		r.log.Warnf("Failed to open incoming data channel on stream %d: %v", sid, err)
		if closeErr := stream.Close(); closeErr != nil {
			r.log.Debugf("Failed to close stream %d: %v", sid, closeErr)
		}

		return
	}

	if !r.isCurrentAssociation(assoc) {
		_ = dc.Close()

		return
	}

	var (
		maxRetransmits    *uint16
		maxPacketLifeTime *uint16
	)
	val := uint16(dc.Config.ReliabilityParameter) //nolint:gosec //G115
	ordered := true

	switch dc.Config.ChannelType {
	case datachannel.ChannelTypeReliable:
		ordered = true
	case datachannel.ChannelTypeReliableUnordered:
		ordered = false
	case datachannel.ChannelTypePartialReliableRexmit:
		ordered = true
		maxRetransmits = &val
	case datachannel.ChannelTypePartialReliableRexmitUnordered:
		ordered = false
		maxRetransmits = &val
	case datachannel.ChannelTypePartialReliableTimed:
		ordered = true
		maxPacketLifeTime = &val
	case datachannel.ChannelTypePartialReliableTimedUnordered:
		ordered = false
		maxPacketLifeTime = &val
	default:
	}

	rtcDC, err := r.api.newDataChannel(&DataChannelParameters{
		ID:                &sid,
		Label:             dc.Config.Label,
		Protocol:          dc.Config.Protocol,
		Negotiated:        dc.Config.Negotiated,
		Ordered:           ordered,
		MaxPacketLifeTime: maxPacketLifeTime,
		MaxRetransmits:    maxRetransmits,
	}, r, r.api.settingEngine.LoggerFactory.NewLogger("ortc"))
	if err != nil {
		// This data channel is invalid. Close it and log an error.
		if err1 := dc.Close(); err1 != nil {
			r.log.Errorf("Failed to close invalid data channel: %v", err1)
		}
		r.log.Errorf("Failed to accept data channel: %v", err)
		r.onError(err)

		return
	}

	accepted, err := r.onDataChannel(rtcDC, assoc, stream)
	if err != nil {
		_ = dc.Close()

		return
	}
	<-accepted
	if !r.isDataChannelBound(rtcDC, assoc, stream) {
		return
	}
	rtcDC.handleOpen(dc, true, dc.Config.Negotiated)

	r.lock.Lock()
	r.dataChannelsOpened++
	handler := r.onDataChannelOpenedHandler
	r.lock.Unlock()

	if handler != nil {
		handler(rtcDC)
	}
}

func (r *SCTPTransport) isCurrentAssociation(assoc *sctp.Association) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.sctpAssociation != nil && r.sctpAssociation == assoc
}

// OnError sets an event handler which is invoked when the SCTP Association errors.
func (r *SCTPTransport) OnError(f func(err error)) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.onErrorHandler = f
}

func (r *SCTPTransport) onError(err error) {
	r.lock.RLock()
	handler := r.onErrorHandler
	r.lock.RUnlock()

	if handler != nil {
		go handler(err)
	}
}

// OnClose sets an event handler which is invoked when the SCTP Association closes.
func (r *SCTPTransport) OnClose(f func(err error)) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.onCloseHandler = f
}

func (r *SCTPTransport) onClose(err error) {
	r.lock.RLock()
	handler := r.onCloseHandler
	r.lock.RUnlock()

	if handler != nil {
		go handler(err)
	}
}

// OnDataChannel sets an event handler which is invoked when a data
// channel message arrives from a remote peer.
func (r *SCTPTransport) OnDataChannel(f func(*DataChannel)) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.onDataChannelHandler = f
}

// OnDataChannelOpened sets an event handler which is invoked when a data
// channel is opened.
func (r *SCTPTransport) OnDataChannelOpened(f func(*DataChannel)) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.onDataChannelOpenedHandler = f
}

func (r *SCTPTransport) onDataChannel(dc *DataChannel, association *sctp.Association, stream *sctp.Stream) (done chan struct{}, err error) {
	r.lock.Lock()
	if err = r.bindDataChannelLocked(dc, association, stream); err != nil {
		r.lock.Unlock()

		return nil, err
	}
	r.dataChannels = append(r.dataChannels, dc)
	r.dataChannelsAccepted++
	handler := r.onDataChannelHandler
	r.lock.Unlock()

	done = make(chan struct{})
	if handler == nil || dc == nil {
		close(done)

		return
	}

	// Run this synchronously to allow setup done in onDataChannelFn()
	// to complete before datachannel event handlers might be called.
	go func() {
		handler(dc)
		close(done)
	}()

	return
}

func (r *SCTPTransport) updateMaxChannels() {
	maxChannels := maxChannelsForAssociation(r.association())
	r.lock.Lock()
	r.maxChannels = maxChannels
	r.lock.Unlock()
}

func maxChannelsForAssociation(association *sctp.Association) *uint16 {
	maxChannels := sctpMaxChannels
	if association != nil {
		if metadata, ok := association.Metadata(); ok {
			maxChannels = min(maxChannels, metadata.NumInboundStreams, metadata.NumOutboundStreams)
		}
	}

	return &maxChannels
}

func (r *SCTPTransport) releaseDataChannelID(streamID uint16) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.releaseDataChannelIDLocked(streamID)
}

func (r *SCTPTransport) onStreamResetComplete(association *sctp.Association, streamID uint16) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.sctpAssociation == association && r.state == SCTPTransportStateConnected {
		r.releaseDataChannelIDLocked(streamID)
	}
}

// The caller must hold r.lock. Reset callbacks carry only SID, so consume the
// oldest bound stream's token, including an already released failed open.
func (r *SCTPTransport) releaseDataChannelIDLocked(streamID uint16) {
	queue := r.dataChannelResetReservations[streamID]
	if len(queue) == 0 {
		// Legacy callers/tests can reserve an ID without binding a stream.
		if len(r.dataChannelReservations) == 0 {
			if generations := r.localDataChannelGenerations[streamID]; len(generations) <= 1 {
				delete(r.localDataChannelGenerations, streamID)
			} else {
				r.localDataChannelGenerations[streamID] = generations[1:]
			}
			r.releaseDataChannelIDCount(streamID, 1)
		}

		return
	}
	oldest := queue[0]
	queue[0] = nil
	if len(queue) == 1 {
		delete(r.dataChannelResetReservations, streamID)
	} else {
		r.dataChannelResetReservations[streamID] = queue[1:]
	}
	reservation, ok := r.dataChannelReservations[oldest.owner]
	if ok && reservation.resetReservation == oldest {
		r.releaseDataChannelReservation(oldest.owner)
	}
	r.discardLocalDataChannelGenerationLocked(streamID, oldest)
}

func (r *SCTPTransport) discardFailedDataChannel(dataChannel *DataChannel) {
	r.lock.Lock()
	defer r.lock.Unlock()

	for i, existing := range r.dataChannels {
		if existing != dataChannel {
			continue
		}
		copy(r.dataChannels[i:], r.dataChannels[i+1:])
		r.dataChannels[len(r.dataChannels)-1] = nil
		r.dataChannels = r.dataChannels[:len(r.dataChannels)-1]

		break
	}
	r.releaseDataChannelReservation(weak.Make(dataChannel))
}

// MaxChannels is the maximum number of RTCDataChannels that can be open simultaneously.
func (r *SCTPTransport) MaxChannels() uint16 {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.maxChannels == nil {
		return sctpMaxChannels
	}

	return *r.maxChannels
}

// State returns the current state of the SCTPTransport.
func (r *SCTPTransport) State() SCTPTransportState {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.state
}

// Metadata returns negotiated SCTP association metadata. The ok return value is
// false until the SCTP association has been established.
func (r *SCTPTransport) Metadata() (SCTPTransportMetadata, bool) {
	association := r.association()
	if association == nil {
		return SCTPTransportMetadata{}, false
	}

	metadata, ok := association.Metadata()
	if !ok {
		return SCTPTransportMetadata{}, false
	}

	return newSCTPTransportMetadata(metadata), true
}

// Stats reports the current statistics of the SCTPTransport.
func (r *SCTPTransport) Stats() SCTPTransportStats {
	stats := SCTPTransportStats{
		Timestamp: statsTimestampFrom(time.Now()),
		Type:      StatsTypeSCTPTransport,
		ID:        "sctpTransport",
	}

	association := r.association()
	if association != nil {
		stats.BytesSent = association.BytesSent()
		stats.BytesReceived = association.BytesReceived()
		stats.SmoothedRoundTripTime = association.SRTT() * 0.001 // convert milliseconds to seconds
		stats.CongestionWindow = association.CWND()
		stats.ReceiverWindow = association.RWND()
		stats.MTU = association.MTU()
		if metadata, ok := association.Metadata(); ok {
			transportMetadata := newSCTPTransportMetadata(metadata)
			stats.Metadata = &transportMetadata
		}
	}

	return stats
}

func (r *SCTPTransport) collectStats(collector *statsReportCollector) {
	collector.Collecting()
	stats := r.Stats()
	collector.Collect(stats.ID, stats)
}

func (r *SCTPTransport) generateAndSetDataChannelID(dtlsRole DTLSRole, idOut **uint16, channel *DataChannel) error {
	var firstID uint32
	if dtlsRole != DTLSRoleClient {
		firstID++
	}

	r.lock.Lock()
	defer r.lock.Unlock()
	maxVal := uint32(sctpMaxChannels)
	if r.maxChannels != nil {
		maxVal = uint32(*r.maxChannels)
	}

	if maxVal <= firstID {
		return &rtcerr.OperationError{Err: ErrMaxDataChannelID}
	}
	start := uint32(r.nextDataChannelID)
	if start < firstID || start >= maxVal || start%2 != firstID {
		start = firstID
	}
	candidateCount := (maxVal - firstID + 1) / 2
	for range candidateCount {
		candidate := start
		start += 2
		if start >= maxVal {
			start = firstID
		}
		id := uint16(candidate)
		if _, ok := r.dataChannelIDsUsed[id]; ok {
			continue
		}
		*idOut = &id
		r.reserveDataChannelID(channel, id)
		r.nextDataChannelID = uint16(start)

		return nil
	}

	return &rtcerr.OperationError{Err: ErrMaxDataChannelID}
}

func (r *SCTPTransport) association() *sctp.Association {
	if r == nil {
		return nil
	}
	r.lock.RLock()
	association := r.sctpAssociation
	r.lock.RUnlock()

	return association
}

// BufferedAmount returns total amount (in bytes) of currently buffered user data.
func (r *SCTPTransport) BufferedAmount() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.sctpAssociation == nil {
		return 0
	}

	return r.sctpAssociation.BufferedAmount()
}

// GetSctpInit returns the current sctp-init attribute and caches the last created.
// The caller should hold the lock.
func (r *SCTPTransport) GetSctpInit() []byte {
	if len(r.localSctpInit) == 0 {
		var err error
		r.localSctpInit, err = sctp.GenerateOutOfBandToken(sctp.Config{
			MaxReceiveBufferSize: r.api.settingEngine.sctp.maxReceiveBufferSize,
			NumInboundStreams:    r.api.settingEngine.sctp.numInboundStreams,
			NumOutboundStreams:   r.api.settingEngine.sctp.numOutboundStreams,
			EnableZeroChecksum:   r.api.settingEngine.sctp.enableZeroChecksum,
		})
		if err != nil {
			r.log.Warnf("Failed to create sctp-init: %v", err)
		}
	}

	return r.localSctpInit
}

func (r *SCTPTransport) setAssociation(association *sctp.Association) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.sctpAssociation = association
	r.state = SCTPTransportStateConnected
	r.associationGeneration = 0
	r.maxChannels = maxChannelsForAssociation(association)
	association.OnStreamResetComplete(func(streamID uint16) {
		r.onStreamResetComplete(association, streamID)
	})
	association.OnAssociationRestart(func(event sctp.AssociationRestartEvent) {
		r.onAssociationRestart(association, event)
	})
}

func (r *SCTPTransport) setMaxChannels(inbound, outbound uint16) {
	value := min(inbound, outbound)
	r.maxChannels = &value
}

func (r *SCTPTransport) onAssociationRestart(association *sctp.Association, event sctp.AssociationRestartEvent) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.sctpAssociation != association || r.state != SCTPTransportStateConnected ||
		event.Generation <= r.associationGeneration {
		return
	}
	r.associationGeneration = event.Generation
	r.setMaxChannels(event.NumInboundStreams, event.NumOutboundStreams)
	retained := make(map[*sctp.Stream]struct{}, len(event.RetainedStreams))
	for _, stream := range event.RetainedStreams {
		retained[stream] = struct{}{}
	}
	for channel, reservation := range r.dataChannelReservations {
		if reservation.association.Value() != association || reservation.generation >= event.Generation {
			continue
		}
		if _, ok := retained[reservation.stream.Value()]; ok {
			reservation.generation = event.Generation
			r.dataChannelReservations[channel] = reservation

			continue
		}
		r.releaseDataChannelReservation(channel)
	}
	r.reconcileDataChannelResetReservations(association, event, retained)
}

func (r *SCTPTransport) reserveDataChannelID(channel *DataChannel, id uint16) {
	if channel == nil {
		r.dataChannelIDsUsed[id]++

		return
	}
	if r.dataChannelReservations == nil {
		r.dataChannelReservations = make(map[weak.Pointer[DataChannel]]dataChannelReservation)
	}
	key := weak.Make(channel)
	if _, ok := r.dataChannelReservations[key]; ok {
		return
	}
	r.dataChannelReservations[key] = dataChannelReservation{id: id}
	r.dataChannelIDsUsed[id]++
}

func (r *SCTPTransport) releaseDataChannelReservation(channel weak.Pointer[DataChannel]) {
	reservation, ok := r.dataChannelReservations[channel]
	if !ok {
		return
	}
	delete(r.dataChannelReservations, channel)
	if reservation.resetReservation != nil {
		r.discardLocalDataChannelGenerationLocked(reservation.id, reservation.resetReservation)
	}
	r.releaseDataChannelIDCount(reservation.id, 1)
}

func (r *SCTPTransport) releaseDataChannelIDCount(id uint16, count uint32) {
	if r.dataChannelIDsUsed[id] <= count {
		delete(r.dataChannelIDsUsed, id)
	} else {
		r.dataChannelIDsUsed[id] -= count
	}
}

func (r *SCTPTransport) bindDataChannel(channel *DataChannel, association *sctp.Association, stream *sctp.Stream) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	return r.bindDataChannelLocked(channel, association, stream)
}

func (r *SCTPTransport) isDataChannelBound(channel *DataChannel, association *sctp.Association, stream *sctp.Stream) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()
	reservation, ok := r.dataChannelReservations[weak.Make(channel)]

	return ok && r.sctpAssociation == association && r.state == SCTPTransportStateConnected &&
		reservation.association.Value() == association && reservation.stream.Value() == stream && stream.State() == sctp.StreamStateOpen
}

func (r *SCTPTransport) bindDataChannelLocked(channel *DataChannel, association *sctp.Association, stream *sctp.Stream) error {
	if stream == nil {
		r.releaseDataChannelReservation(weak.Make(channel))

		return io.ErrClosedPipe
	}
	// Capture the generation before checking state. A discarded stream also
	// advances its generation during restart, but is no longer open.
	generation := stream.AssociationGeneration()
	if r.sctpAssociation != association || r.state != SCTPTransportStateConnected || stream.State() != sctp.StreamStateOpen {
		r.releaseDataChannelReservation(weak.Make(channel))

		return io.ErrClosedPipe
	}
	if !r.isDataChannelBindingWithinLimit(channel, association, stream.StreamIdentifier(), stream) {
		r.releaseDataChannelReservation(weak.Make(channel))

		return &rtcerr.OperationError{Err: ErrMaxDataChannelID}
	}
	r.reserveDataChannelID(channel, stream.StreamIdentifier())
	key := weak.Make(channel)
	reservation := r.dataChannelReservations[key]
	reservation.association = weak.Make(association)
	reservation.stream = weak.Make(stream)
	reservation.generation = generation
	if reservation.resetReservation == nil || reservation.resetReservation.stream.Value() != stream {
		token := &dataChannelResetReservation{owner: key, association: weak.Make(association), stream: weak.Make(stream), generation: generation}
		reservation.resetReservation = token
		if r.dataChannelResetReservations == nil {
			r.dataChannelResetReservations = make(map[uint16][]*dataChannelResetReservation)
		}
		r.dataChannelResetReservations[reservation.id] = append(r.dataChannelResetReservations[reservation.id], token)
	}
	r.dataChannelReservations[key] = reservation

	return nil
}

// The caller must hold r.lock. Drop precisely the old discarded generations,
// including detached channels and failed-open tokens with no reservation left.
func (r *SCTPTransport) reconcileDataChannelResetReservations(association *sctp.Association, event sctp.AssociationRestartEvent, retained map[*sctp.Stream]struct{}) {
	for id, queue := range r.dataChannelResetReservations {
		kept := queue[:0]
		for _, token := range queue {
			if token.association.Value() == association && token.generation < event.Generation {
				if _, ok := retained[token.stream.Value()]; !ok {
					r.discardLocalDataChannelGenerationLocked(id, token)

					continue
				}
				token.generation = event.Generation
			}
			kept = append(kept, token)
		}
		clear(queue[len(kept):])
		if len(kept) == 0 {
			delete(r.dataChannelResetReservations, id)
		} else {
			r.dataChannelResetReservations[id] = kept
		}
	}
}

func (r *SCTPTransport) isDataChannelBindingWithinLimit(channel *DataChannel, association *sctp.Association, id uint16, stream *sctp.Stream) bool {
	limit := sctpMaxChannels
	if r.maxChannels != nil {
		limit = *r.maxChannels
	}
	if id < limit {
		return true
	}
	reservation, ok := r.dataChannelReservations[weak.Make(channel)]
	boundStream := reservation.stream.Value()

	return ok && reservation.id == id && reservation.association.Value() == association && boundStream != nil &&
		(stream == nil || boundStream == stream)
}

func (r *SCTPTransport) validateDataChannelID(channel *DataChannel, association *sctp.Association, id uint16) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.isDataChannelBindingWithinLimit(channel, association, id, nil) {
		return nil
	}
	r.releaseDataChannelReservation(weak.Make(channel))

	return &rtcerr.OperationError{Err: ErrMaxDataChannelID}
}
