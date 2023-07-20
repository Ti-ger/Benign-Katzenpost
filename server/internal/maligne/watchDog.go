package maligne

import (
	"math"
	"time"

	"github.com/katzenpost/katzenpost/core/monotime"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"gopkg.in/op/go-logging.v1"
)

type watchDog struct {
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	InCh      chan [16]byte
	outCh     chan []byte
	queue     surbMemoryQueue
	recipient []byte
}

func (w *watchDog) worker() {
	var timer *time.Timer
	/* TODO */
	timer = time.NewTimer(1 * time.Second)
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
		case <-w.HaltCh():
			// Th-th-th-that's all folks.
			w.log.Debugf("Terminating gracefully.")
			return
		case <-timer.C:
			w.log.Debugf("Timer was triggered!")
			for {
				// Peek at the next packet in the queue.
				dispatchAt, _, err := w.queue.Peek()
				if err != nil {
					// The queue is empty, just reschedule for the max duration,
					// when there are packets to schedule, we'll get woken up.
					w.log.Debugf("Queue was empty!")
					timer.Reset(math.MaxInt64)
					break
				}

				// Figure out if the packet needs to be handled now.
				now := monotime.Now()
				if dispatchAt > now {
					w.log.Debugf("DispatchAt: %d > %d now", dispatchAt, now)
					// Packet dispatch will happen at a later time, so schedule
					// the next timer tick, and go back to waiting for something
					// interesting to happen.
					timer.Reset(dispatchAt - now)
					break
				}

				// We waited long enough for this packet so remove it from the
				// queue
				w.queue.Pop()
				w.log.Debug("Dropped Surb")
			}

		case surb := <-w.InCh:
			w.log.Debugf("Received SURB ID: %v", surb)
			w.queue.Enqueue(surb)
			// Peek at the next packet in the queue.
			dispatchAt, _, err := w.queue.Peek()
			if err != nil {
				// Figure out if the packet needs to be handled now.
				now := monotime.Now()
				timer.Reset(dispatchAt - now)
			} else {
				timer.Reset(1 * time.Second)
			}
			w.log.Debugf("Queue has now length: %d", w.queue.q.Len())
			if w.queue.q.Len() >= ATTACK_THRESHHOLD {
				w.log.Debugf("Attack threshhold reached")
				w.outCh <- w.recipient
				w.log.Debugf("Notified main worker")
			}

		}
	}

	// NOTREACHED
}

// New constructs a new scheduler instance.
func NewWatchDog(glue glue.Glue, outchannel chan []byte, recipient []byte) (*watchDog, error) {

	log := glue.LogBackend().GetLogger("watchdog " + string(recipient))
	w := &watchDog{
		glue:      glue,
		log:       log,
		InCh:      make(chan [16]byte),
		outCh:     outchannel,
		queue:     *newMemoryQueue(glue, log),
		recipient: recipient,
	}

	w.Go(w.worker)
	return w, nil
}
