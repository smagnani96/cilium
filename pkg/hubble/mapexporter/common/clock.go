// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package common

import (
	"time"

	"github.com/cilium/cilium/pkg/maps/timestamp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BPFClock converts a raw datapath timestamp into wall-clock time.
// Those fields are usually stored in kernel-clock units local to this node,
// and not comparable across nodes.
type BPFClock struct {
	Now       time.Time
	NowCTSec  int64
	Converter timestamp.TimestampConverter
}

// NewBPFClock samples the current wall-clock.
func NewBPFClock() (BPFClock, error) {
	clockSource := timestamp.GetClockSourceFromOptions()
	converter, err := timestamp.NewCTTimeToSecConverter(clockSource)
	if err != nil {
		return BPFClock{}, err
	}
	nowCT, err := timestamp.GetCTCurTime(clockSource)
	if err != nil {
		return BPFClock{}, err
	}
	return BPFClock{
		Now:       time.Now(),
		NowCTSec:  int64(converter(nowCT)),
		Converter: converter,
	}, nil
}

// ToWallClock converts ctTime to the wall-clock time it corresponds to.
func (c BPFClock) ToWallClock(ctTime uint32) *timestamppb.Timestamp {
	if c.Converter == nil {
		return nil
	}
	diffSec := int64(c.Converter(uint64(ctTime))) - c.NowCTSec
	return timestamppb.New(c.Now.Add(time.Duration(diffSec) * time.Second))
}
