// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package webrtc

// GizClaw regression suite.
//
// These tests only live on the GizClaw fork's gizclaw integration branch. They
// drive real PeerConnection pairs over a virtual network the way GizClaw uses
// them: one long-lived association carrying one short-lived DataChannel per
// request. Each stage reproduces a problem GizClaw hit in production or
// qualification, and TestGizclawChainedLifecycle runs all stages back to back
// on a single association, checking liveness and resource baselines between
// them.
//
//   - Bursts of new DataChannels under receive-window pressure, the load behind
//     the 2026-09-10 Edge accept wedge (GizClaw/gizclaw#1213, #1226,
//     pion/webrtc#3535; the lost-OPEN wedge itself is reproduced at wire level
//     in sctptransport_accept_test.go).
//   - DataChannel ID exhaustion on long-lived associations and ID reuse after
//     stream reset (GizClaw/gizclaw#776, pion/webrtc#3534, pion/sctp#494).
//   - Concurrent closes leaving remote streams open because stream resets were
//     not serialized (GizClaw/gizclaw#1143).
//   - Stream resets never completing after partially reliable data is
//     abandoned, and retransmission recovery under packet loss (pion-sctp
//     "Complete pending stream resets after FORWARD-TSN", "Rearm T3 after RACK
//     tail loss probe").
//
// Known, unfixed issues found by this suite are skipped unless
// GIZCLAW_KNOWN_ISSUES=1: TestGizclawFragmentedMessagesExceedingReceiveWindow,
// TestGizclawImmediateDataChannelIDReuse and
// TestGizclawClosedStreamEchoesUnderLossExceedingWindow.
//
// Run with: go test -race -run 'TestGizclaw|TestSCTPTransportAcceptDataChannels' -v .
// -short scales the workloads down.

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/logging"
	"github.com/pion/transport/v4/vnet"
	"github.com/stretchr/testify/require"
)

const gizRequestTimeout = 20 * time.Second

type gizPairConfig struct {
	// answerReceiveBuffer is the answerer's SCTP receive buffer. A small value
	// puts the association under receive-window pressure.
	answerReceiveBuffer uint32
	// numStreams is the negotiated SCTP stream count on both sides. A small
	// value forces DataChannel ID reuse.
	numStreams uint16
	// oneWayDelay is added to every packet crossing the virtual router.
	oneWayDelay time.Duration
	// loggerFactory, if set, is used for both peers.
	loggerFactory logging.LoggerFactory
}

func (cfg gizPairConfig) logger() logging.LoggerFactory {
	if cfg.loggerFactory != nil {
		return cfg.loggerFactory
	}

	return logging.NewDefaultLoggerFactory()
}

// gizPair is an offerer (client) and answerer (server) connected over vnet.
// The answerer echoes every message back on the channel it arrived on.
type gizPair struct {
	t             *testing.T
	offer, answer *PeerConnection
	wan           *vnet.Router

	// lossPercent is the share of DTLS records (and therefore SCTP packets)
	// the router drops. STUN is never dropped so ICE stays connected.
	lossPercent atomic.Int32
	dropped     atomic.Int64

	remoteClosed atomic.Int64

	// baseline holds each side's registered channels and reserved IDs once
	// only the control channel exists.
	baseline [4]int
}

func newGizPair(t *testing.T, cfg gizPairConfig) *gizPair {
	t.Helper()

	pair := &gizPair{t: t}
	loggerFactory := cfg.logger()

	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "1.2.3.0/24",
		MinDelay:      cfg.oneWayDelay,
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)
	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		pct := pair.lossPercent.Load()
		if pct == 0 {
			return true
		}
		data := c.UserData()
		// DTLS content types are 20..63; STUN starts with 0 or 1.
		if len(data) == 0 || data[0] < 20 || data[0] > 63 {
			return true
		}
		if rand.IntN(100) < int(pct) { //nolint:gosec // test-only loss model
			pair.dropped.Add(1)

			return false
		}

		return true
	})

	newAPI := func(ip string, receiveBuffer uint32) *API {
		nw, netErr := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
		require.NoError(t, netErr)
		require.NoError(t, wan.AddNet(nw))

		se := SettingEngine{}
		se.SetNet(nw)
		se.SetICETimeouts(5*time.Second, 10*time.Second, 200*time.Millisecond)
		se.LoggerFactory = loggerFactory
		// Match pkgs/giznet/gizwebrtc: detached channels and a bounded SCTP
		// handshake retransmission timeout.
		se.DetachDataChannels()
		se.SetSCTPHandshakeRTOMax(150 * time.Millisecond)
		if receiveBuffer != 0 {
			se.SetSCTPMaxReceiveBufferSize(receiveBuffer)
		}
		if cfg.numStreams != 0 {
			se.SetSCTPNumStreams(cfg.numStreams, cfg.numStreams)
		}

		return NewAPI(WithSettingEngine(se))
	}
	offerAPI := newAPI("1.2.3.4", 0)
	answerAPI := newAPI("1.2.3.5", cfg.answerReceiveBuffer)
	require.NoError(t, wan.Start())
	pair.wan = wan

	pair.offer, err = offerAPI.NewPeerConnection(Configuration{})
	require.NoError(t, err)
	pair.answer, err = answerAPI.NewPeerConnection(Configuration{})
	require.NoError(t, err)

	t.Cleanup(func() {
		closePairNow(t, pair.offer, pair.answer)
		require.NoError(t, wan.Stop())
	})

	pair.answer.OnDataChannel(pair.serve)

	// SCTP is only negotiated when a DataChannel exists before the offer.
	control, err := pair.offer.CreateDataChannel("control", nil)
	require.NoError(t, err)
	opened := make(chan struct{})
	control.OnOpen(func() { close(opened) })
	require.NoError(t, signalPairWithOptions(pair.offer, pair.answer, withDisableInitialDataChannel(true)))
	select {
	case <-opened:
	case <-time.After(15 * time.Second):
		t.Fatal("control DataChannel did not open")
	}

	pair.probe("after connect")
	// Only the control channel should remain reserved on either side.
	gizEventually(t, gizRequestTimeout, func() bool {
		_, oi := sctpChannelCounts(pair.offer)
		_, ai := sctpChannelCounts(pair.answer)

		return oi == 1 && ai == 1
	}, func() string { return "IDs other than the control channel stayed reserved after connect" })
	pair.baseline = pair.counts()

	return pair
}

// serve is the answerer's handler: detach each channel and echo every
// message until the peer closes it.
func (p *gizPair) serve(dc *DataChannel) {
	dc.OnOpen(func() {
		raw, err := dc.Detach()
		if err != nil {
			return
		}
		p.echo(raw)
	})
}

func (p *gizPair) echo(raw datachannel.ReadWriteCloser) {
	defer p.remoteClosed.Add(1)
	defer func() { _ = raw.Close() }()
	buf := make([]byte, 64*1024)
	for {
		n, err := raw.Read(buf)
		if err != nil {
			return
		}
		if _, err := raw.Write(expectedReply(buf[:n])); err != nil {
			return
		}
	}
}

// expectedReply is the answerer's echo: a short acknowledgement for large
// payloads to keep the reverse direction light, the payload itself otherwise.
func expectedReply(payload []byte) []byte {
	if len(payload) > 1024 {
		return []byte(fmt.Sprintf("ack:%d", len(payload)))
	}

	return payload
}

// request opens one DataChannel, sends payload, waits for the echo and closes
// the channel, mirroring one GizClaw RPC.
func (p *gizPair) request(label string, payload []byte, init *DataChannelInit) error {
	return p.requestN(label, payload, 1, init)
}

// requestN is request with count messages sent back to back before reading
// the count replies.
func (p *gizPair) requestN(label string, payload []byte, count int, init *DataChannelInit) error {
	raw, err := p.openDetached(label, init)
	if err != nil {
		return err
	}

	result := make(chan error, 1)
	go func() {
		for range count {
			if _, err := raw.Write(payload); err != nil {
				result <- fmt.Errorf("send %s: %w", label, err)

				return
			}
		}
		want := expectedReply(payload)
		buf := make([]byte, 64*1024)
		for i := range count {
			n, err := raw.Read(buf)
			if err != nil {
				result <- fmt.Errorf("read %s reply %d/%d: %w", label, i+1, count, err)

				return
			}
			if !bytes.Equal(buf[:n], want) {
				result <- fmt.Errorf("%s: got %d-byte reply, want %q", label, n, want)

				return
			}
		}
		result <- nil
	}()

	select {
	case err = <-result:
	case <-time.After(gizRequestTimeout):
		err = fmt.Errorf("%s (stream %d): replies not received within %s", label, streamID(raw), gizRequestTimeout)
	}
	if closeErr := raw.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("close %s: %w", label, closeErr)
	}

	return err
}

// openDetached creates a DataChannel and returns its detached stream once it
// is open.
func (p *gizPair) openDetached(label string, init *DataChannelInit) (datachannel.ReadWriteCloser, error) {
	dc, err := p.offer.CreateDataChannel(label, init)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", label, err)
	}
	type detached struct {
		raw datachannel.ReadWriteCloser
		err error
	}
	opened := make(chan detached, 1)
	dc.OnOpen(func() {
		raw, err := dc.Detach()
		opened <- detached{raw, err}
	})
	select {
	case d := <-opened:
		if d.err != nil {
			return nil, fmt.Errorf("detach %s: %w", label, d.err)
		}

		return d.raw, nil
	case <-time.After(gizRequestTimeout):
		_ = dc.Close()

		return nil, fmt.Errorf("%s did not open within %s", label, gizRequestTimeout)
	}
}

// probe proves the association can still open a new DataChannel and move
// data in both directions.
func (p *gizPair) probe(stage string) {
	p.t.Helper()
	require.NoError(p.t, p.request("probe", []byte("ping "+stage), nil), "liveness probe %s", stage)
}

func sctpChannelCounts(pc *PeerConnection) (channels, ids int) {
	r := pc.SCTP()
	r.lock.RLock()
	defer r.lock.RUnlock()

	return len(r.dataChannels), len(r.dataChannelIDsUsed)
}

func (p *gizPair) counts() [4]int {
	oc, oi := sctpChannelCounts(p.offer)
	ac, ai := sctpChannelCounts(p.answer)

	return [4]int{oc, oi, ac, ai}
}

// requireBaseline waits until both transports are back to the state right
// after connect: every closed DataChannel was unregistered and its ID
// released.
func (p *gizPair) requireBaseline(stage string) {
	p.t.Helper()
	gizEventually(p.t, 30*time.Second, func() bool {
		return p.counts() == p.baseline
	}, func() string {
		c := p.counts()

		return fmt.Sprintf("%s: offer channels=%d ids=%d, answer channels=%d ids=%d; baseline %v",
			stage, c[0], c[1], c[2], c[3], p.baseline)
	})
}

// gizEventually waits for cond and, on timeout, fails with msg evaluated at
// that moment (require.Eventually formats its message before waiting).
func gizEventually(t *testing.T, timeout time.Duration, cond func() bool, msg func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s: %s", timeout, msg())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func scaled(t *testing.T, full, short int) int {
	t.Helper()
	if testing.Short() {
		return short
	}

	return full
}

// runConcurrent runs n jobs with at most workers in flight and returns the
// first error.
func runConcurrent(n, workers int, job func(i int) error) error {
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		next     atomic.Int64
	)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				if err := job(i); err != nil {
					mu.Lock()
					firstErr = errors.Join(firstErr, err)
					mu.Unlock()

					return
				}
			}
		}()
	}
	wg.Wait()

	return firstErr
}

// stageBurst opens n DataChannels at once, each sending messages
// single-chunk messages as soon as it opens, against a small answerer receive
// buffer. It is a load regression for the accept path under receive-window
// pressure: with the serial accept loop it takes 20-30x longer. It does not by
// itself reproduce the permanent accept wedge of the 2026-09-10 Edge incident,
// which needs one stream's DCEP OPEN to be lost; the wire-level tests in
// sctptransport_accept_test.go cover that. Messages stay below one SCTP
// fragment; see TestGizclawFragmentedMessagesExceedingReceiveWindow for
// fragmented ones.
func stageBurst(p *gizPair, n, messages int) {
	p.t.Helper()
	payload := bytes.Repeat([]byte{'b'}, 1000)
	err := runConcurrent(n, n, func(i int) error {
		return p.requestN(fmt.Sprintf("burst-%d", i), payload, messages, nil)
	})
	require.NoError(p.t, err, "burst of %d channels x %d messages", n, messages)
}

// stageChurn runs total request-scoped channels with concurrency in flight.
// When total exceeds the negotiated stream IDs, every ID is reused many times,
// which only works if every closed channel's ID is released after its reset.
func stageChurn(p *gizPair, total, concurrency int) {
	p.t.Helper()
	var exhausted atomic.Int64
	err := runConcurrent(total, concurrency, func(i int) error {
		label := fmt.Sprintf("churn-%d", i)
		payload := []byte(fmt.Sprintf("req-%d", i))
		deadline := time.Now().Add(gizRequestTimeout)
		for {
			err := p.request(label, payload, nil)
			// With a small ID space, IDs whose reset is still completing are
			// briefly unavailable; they must come back, so retry until the
			// request deadline.
			if !errors.Is(err, ErrMaxDataChannelID) || time.Now().After(deadline) {
				return err
			}
			exhausted.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	})
	require.NoError(p.t, err, "churn of %d requests with concurrency %d", total, concurrency)
	if n := exhausted.Load(); n > 0 {
		p.t.Logf("churn: %d transient ErrMaxDataChannelID while resets completed", n)
	}
}

// stageMassClose opens n channels, then closes all of them at the same time,
// half from each side, so many stream resets are in flight together. Every
// stream on both sides must observe the close.
func stageMassClose(p *gizPair, n int) {
	p.t.Helper()

	accepted := make(chan datachannel.ReadWriteCloser, n)
	p.answer.OnDataChannel(func(dc *DataChannel) {
		dc.OnOpen(func() {
			if raw, err := dc.Detach(); err == nil {
				accepted <- raw
			}
		})
	})
	defer p.answer.OnDataChannel(p.serve)

	var closedLocal, closedRemote atomic.Int64
	watch := func(raw datachannel.ReadWriteCloser, counter *atomic.Int64) {
		go func() {
			buf := make([]byte, 1024)
			for {
				if _, err := raw.Read(buf); err != nil {
					// Like a real application, close our side once the
					// peer's reset ends the stream.
					_ = raw.Close()
					counter.Add(1)

					return
				}
			}
		}()
	}

	local := make([]datachannel.ReadWriteCloser, 0, n)
	for i := range n {
		raw, err := p.openDetached(fmt.Sprintf("mass-%d", i), nil)
		require.NoError(p.t, err)
		watch(raw, &closedLocal)
		local = append(local, raw)
	}
	remote := make(map[uint16]datachannel.ReadWriteCloser, n)
	deadline := time.After(gizRequestTimeout)
	for len(remote) < n {
		select {
		case raw := <-accepted:
			watch(raw, &closedRemote)
			remote[streamID(raw)] = raw
		case <-deadline:
			p.t.Fatalf("only %d of %d channels accepted", len(remote), n)
		}
	}

	var closers sync.WaitGroup
	for i := range n {
		closers.Add(1)
		go func() {
			defer closers.Done()
			if i%2 == 0 {
				_ = local[i].Close()
			} else {
				_ = remote[streamID(local[i])].Close()
			}
		}()
	}
	closers.Wait()

	gizEventually(p.t, gizRequestTimeout, func() bool {
		return closedLocal.Load() == int64(n) && closedRemote.Load() == int64(n)
	}, func() string {
		return fmt.Sprintf("closes observed: offer %d/%d, answer %d/%d", closedLocal.Load(), n, closedRemote.Load(), n)
	})
}

func streamID(raw datachannel.ReadWriteCloser) uint16 {
	return raw.(interface{ StreamIdentifier() uint16 }).StreamIdentifier() //nolint:forcetypeassert
}

// stageLossy runs request churn plus partially reliable traffic while the
// network drops a share of SCTP packets, then closes the partially reliable
// channels; their stream resets must complete even though some of their data
// was abandoned.
func stageLossy(p *gizPair, lossPercent int32, requests, prChannels, prMessages int) {
	p.t.Helper()
	p.lossPercent.Store(lossPercent)
	defer p.lossPercent.Store(0)

	before := p.remoteClosed.Load()
	zero := uint16(0)
	unordered := false
	prErr := make(chan error, prChannels)
	var wg sync.WaitGroup
	for i := range prChannels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := p.openDetached(fmt.Sprintf("pr-%d", i), &DataChannelInit{
				Ordered: &unordered, MaxRetransmits: &zero,
			})
			if err != nil {
				prErr <- err

				return
			}
			msg := bytes.Repeat([]byte{'p'}, 900)
			for range prMessages {
				if _, err := raw.Write(msg); err != nil {
					prErr <- fmt.Errorf("pr-%d write: %w", i, err)

					return
				}
			}
			if err := raw.Close(); err != nil {
				prErr <- fmt.Errorf("pr-%d close: %w", i, err)
			}
		}()
	}

	stageChurn(p, requests, 4)
	wg.Wait()
	close(prErr)
	for err := range prErr {
		require.NoError(p.t, err)
	}

	// Every channel of this stage, partially reliable ones included, must be
	// seen closed by the answerer.
	want := int64(requests + prChannels)
	gizEventually(p.t, gizRequestTimeout, func() bool {
		return p.remoteClosed.Load()-before == want
	}, func() string {
		return fmt.Sprintf("answerer observed %d of %d closes", p.remoteClosed.Load()-before, want)
	})
	p.t.Logf("lossy stage dropped %d DTLS records", p.dropped.Load())
	require.Positive(p.t, p.dropped.Load(), "loss filter never dropped a packet")
}

func TestGizclawBurstUnderReceiveWindowPressure(t *testing.T) {
	p := newGizPair(t, gizPairConfig{answerReceiveBuffer: 64 * 1024})
	stageBurst(p, scaled(t, 256, 128), 16)
	p.probe("after burst")
	p.requireBaseline("after burst")
}

// gizSCTPRecovery counts pion/sctp log lines that mark SCTP loss recovery:
// T3-rtx timeouts, fast retransmits and RACK loss marking. On a lossless link
// none of them should ever appear. It also counts the "dropped a new stream"
// line of pion/sctp versions that discarded DATA for streams beyond a 16-entry
// accept backlog.
type gizSCTPRecovery struct {
	logging.LoggerFactory
	recoveries atomic.Int64
	drops      atomic.Int64
}

func (f *gizSCTPRecovery) NewLogger(scope string) logging.LeveledLogger {
	return &gizSCTPRecoveryLogger{LeveledLogger: f.LoggerFactory.NewLogger(scope), counts: f}
}

func (f *gizSCTPRecovery) observe(format string) {
	if strings.Contains(format, "dropped a new stream") {
		f.drops.Add(1)
	}
	for _, marker := range []string{"T3-rtx timed out", "fast-retransmit:", "RACK: mark lost", "RACK timer: mark lost"} {
		if strings.Contains(format, marker) {
			f.recoveries.Add(1)
		}
	}
}

type gizSCTPRecoveryLogger struct {
	logging.LeveledLogger
	counts *gizSCTPRecovery
}

func (l *gizSCTPRecoveryLogger) Debugf(format string, args ...any) {
	l.counts.observe(format)
	l.LeveledLogger.Debugf(format, args...)
}

func (l *gizSCTPRecoveryLogger) Tracef(format string, args ...any) {
	l.counts.observe(format)
	l.LeveledLogger.Tracef(format, args...)
}

// TestGizclawNewChannelBurstLatency opens bursts of request channels at once
// over a lossless 28 ms RTT link, like the Edge forwarding a burst of HTTP
// requests. SCTP used to accept at most 16 new streams ahead of the
// application and discard the DATA of any further ones without a SACK, so
// those channels only opened after loss recovery (GizClaw measured p99 3-4 s
// and requests exceeding 5 s). On a lossless link no SCTP loss recovery may
// happen at all, and every request must finish well within the 1 s initial
// RTO.
func TestGizclawNewChannelBurstLatency(t *testing.T) {
	channels := scaled(t, 330, 64)
	rounds := scaled(t, 5, 2)
	logs := &gizSCTPRecovery{LoggerFactory: logging.NewDefaultLoggerFactory()}
	pair := newGizPair(t, gizPairConfig{oneWayDelay: 14 * time.Millisecond, loggerFactory: logs})
	require.Zero(t, logs.recoveries.Load(), "SCTP loss recovery during connect on a lossless link")

	for round := range rounds {
		var slowest atomic.Int64
		err := runConcurrent(channels, channels, func(i int) error {
			start := time.Now()
			err := pair.requestN(fmt.Sprintf("latency-%d-%d", round, i), fmt.Appendf(nil, "req-%d", i), 1, nil)
			elapsed := int64(time.Since(start))
			for {
				prev := slowest.Load()
				if elapsed <= prev || slowest.CompareAndSwap(prev, elapsed) {
					break
				}
			}

			return err
		})
		require.NoError(t, err)
		require.Zero(t, logs.recoveries.Load(),
			"round %d: SCTP loss recovery on a lossless link (%d new streams dropped)", round, logs.drops.Load())
		require.Less(t, time.Duration(slowest.Load()), time.Second,
			"round %d: slowest of %d concurrent requests", round, channels)
	}

	pair.probe("after bursts")
	pair.requireBaseline("after bursts")
}

func TestGizclawRequestChurnReusesDataChannelIDs(t *testing.T) {
	// 128 negotiated streams leave 64 IDs per side, so the churn below reuses
	// every ID many times.
	p := newGizPair(t, gizPairConfig{numStreams: 128})
	stageChurn(p, scaled(t, 600, 150), 1)
	stageChurn(p, scaled(t, 2000, 500), 8)
	p.probe("after churn")
	p.requireBaseline("after churn")
}

// TestGizclawImmediateDataChannelIDReuse is a known, unfixed issue: when the
// ID space is nearly exhausted, an ID released by a completed reset is reused
// at once, and occasionally the answerer's reply on the new channel never
// reaches the offerer even though the answerer read the request and wrote the
// reply. The suspected cause is a race between the offerer releasing the ID
// and the answerer resetting its outgoing stream sequence (MID) for that
// stream. With GizClaw's default 65535 streams, IDs rotate through the whole
// space before reuse, which makes this rare. Set GIZCLAW_KNOWN_ISSUES=1 to run
// it.
func TestGizclawImmediateDataChannelIDReuse(t *testing.T) {
	if os.Getenv("GIZCLAW_KNOWN_ISSUES") == "" {
		t.Skip("known lost reply on immediately reused DataChannel IDs; set GIZCLAW_KNOWN_ISSUES=1")
	}
	// 16 IDs per side with 8 requests in flight forces immediate reuse.
	p := newGizPair(t, gizPairConfig{numStreams: 32})
	stageChurn(p, 300, 8)
	p.probe("after immediate reuse")
	p.requireBaseline("after immediate reuse")
}

func TestGizclawConcurrentCloseCompletesResets(t *testing.T) {
	p := newGizPair(t, gizPairConfig{})
	stageMassClose(p, scaled(t, 300, 100))
	p.probe("after mass close")
	p.requireBaseline("after mass close")
}

func TestGizclawLossyPartialReliableClose(t *testing.T) {
	p := newGizPair(t, gizPairConfig{})
	// 8 x 100 x 900 B of partially reliable data (and as much echoed back)
	// stays below the offerer's 1 MiB receive buffer; see
	// TestGizclawClosedStreamEchoesUnderLossExceedingWindow for more.
	stageLossy(p, 5, scaled(t, 100, 30), 8, scaled(t, 100, 50))
	p.probe("after loss")
	p.requireBaseline("after loss")
}

// TestGizclawClosedStreamEchoesUnderLossExceedingWindow is a known, unfixed
// issue: 8 partially reliable channels each write 200 x 900 B and close
// without reading while request churn runs under 5% loss. The answerer echoes
// everything, about 1.44 MB towards the offerer's 1 MiB receive buffer. After
// the stage the offerer keeps advertising a zero window and drops every new
// DATA chunk, so a fresh DataChannel's reply never arrives and the
// association's receive direction is dead. Without loss, or below the window
// size, the same traffic recovers. Set GIZCLAW_KNOWN_ISSUES=1 to run it.
func TestGizclawClosedStreamEchoesUnderLossExceedingWindow(t *testing.T) {
	if os.Getenv("GIZCLAW_KNOWN_ISSUES") == "" {
		t.Skip("known receive-window wedge after closed-stream echoes under loss; set GIZCLAW_KNOWN_ISSUES=1")
	}
	p := newGizPair(t, gizPairConfig{})
	stageLossy(p, 5, 100, 8, 200)
	p.probe("after loss")
	p.requireBaseline("after loss")
}

// TestGizclawChainedLifecycle runs every stage in sequence on one association,
// as a long-lived GizClaw Server/Edge connection would see them.
func TestGizclawChainedLifecycle(t *testing.T) {
	p := newGizPair(t, gizPairConfig{answerReceiveBuffer: 64 * 1024, numStreams: 1024})

	stageBurst(p, scaled(t, 256, 128), 16)
	p.probe("after burst")
	p.requireBaseline("after burst")

	// 512 IDs per side: the churn reuses each of them several times.
	stageChurn(p, scaled(t, 1500, 400), 16)
	p.probe("after churn")
	p.requireBaseline("after churn")

	stageMassClose(p, scaled(t, 200, 80))
	p.probe("after mass close")
	p.requireBaseline("after mass close")

	stageLossy(p, 5, scaled(t, 100, 30), 8, scaled(t, 100, 50))
	p.probe("after loss")
	p.requireBaseline("after loss")

	// A second burst after everything else proves the accept path recovered.
	stageBurst(p, scaled(t, 256, 128), 16)
	p.probe("after second burst")
	p.requireBaseline("end of lifecycle")
}

// TestGizclawFragmentedMessagesExceedingReceiveWindow is a known, unfixed
// pion/sctp deadlock (also present in upstream v1.11.1): when concurrent
// multi-fragment messages from several streams together exceed the receive
// window, the window fills with partial messages that the application cannot
// read, the fragments that would complete them are dropped for lack of window,
// and the association stops making progress on those streams permanently.
// GizClaw currently avoids it by sizing the receive buffer for its bounded
// stream count (gizwebrtc.GatewaySCTPReceiveBufferSize). Set
// GIZCLAW_KNOWN_ISSUES=1 to run it.
func TestGizclawFragmentedMessagesExceedingReceiveWindow(t *testing.T) {
	if os.Getenv("GIZCLAW_KNOWN_ISSUES") == "" {
		t.Skip("known pion/sctp receive-window deadlock with fragmented messages; set GIZCLAW_KNOWN_ISSUES=1")
	}
	p := newGizPair(t, gizPairConfig{answerReceiveBuffer: 64 * 1024})
	// 5 x 16 KiB = 80 KiB of concurrent fragmented messages into a 64 KiB window.
	payload := bytes.Repeat([]byte{'f'}, 16*1024)
	err := runConcurrent(5, 5, func(i int) error {
		return p.request(fmt.Sprintf("frag-%d", i), payload, nil)
	})
	require.NoError(t, err)
	p.probe("after fragmented burst")
}
