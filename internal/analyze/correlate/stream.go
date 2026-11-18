// Package correlate streams normalized packet records across captures in timestamp order.
package correlate

import (
	"container/heap"
	"context"
	"sync"

	"github.com/zombat/sonic/internal/extract"
	"github.com/zombat/sonic/internal/model"
	"github.com/zombat/sonic/internal/tshark"
)

type capCursor struct {
	capIdx  int
	offset  float64
	records []model.Record
	pos     int
	info    *streamInfo
}

type heapItem struct {
	t      float64
	capIdx int
	frameN int
	rec    *model.Record
	curIdx int
}

type recordHeap []heapItem

func (h recordHeap) Len() int { return len(h) }

func (h recordHeap) Less(i, j int) bool {
	if h[i].t != h[j].t {
		return h[i].t < h[j].t
	}
	if h[i].capIdx != h[j].capIdx {
		return h[i].capIdx < h[j].capIdx
	}
	return h[i].frameN < h[j].frameN
}

func (h recordHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *recordHeap) Push(x any) {
	*h = append(*h, x.(heapItem))
}

func (h *recordHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

// extractAll runs tshark record extraction concurrently across all input captures.
func extractAll(
	ctx context.Context,
	paths []string,
	offsets []float64,
	labels []string,
	maxPackets *int,
) ([]*capCursor, []*streamInfo, error) {
	type result struct {
		out model.RecordsOutput
		err error
	}
	results := make([]result, len(paths))
	sem := make(chan struct{}, min(4, len(paths)))
	var wg sync.WaitGroup
	for i, path := range paths {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out, err := extract.OpenNetworkRecords(ctx, tshark.StreamOptions{
				FilePath:   p,
				MaxPackets: maxPackets,
			})
			results[idx] = result{out: out, err: err}
		}(i, path)
	}
	wg.Wait()

	cursors := make([]*capCursor, len(paths))
	infos := make([]*streamInfo, len(paths))
	for i, res := range results {
		if res.err != nil {
			return nil, nil, res.err
		}
		warns := res.out.Warnings
		if warns == nil {
			warns = []string{}
		}
		info := &streamInfo{
			label:  labels[i],
			path:   paths[i],
			offset: offsets[i],
			back:   res.out.Backend,
			warns:  warns,
		}
		infos[i] = info
		cursors[i] = &capCursor{
			capIdx:  i,
			offset:  offsets[i],
			records: res.out.Records,
			info:    info,
		}
	}
	return cursors, infos, nil
}

// next advances cur by one record while maintaining streaming start/end/done bounds.
func (cur *capCursor) next() (heapItem, bool) {
	if cur.pos >= len(cur.records) {
		cur.info.done = true
		return heapItem{}, false
	}
	rec := &cur.records[cur.pos]
	cur.pos++
	t := rec.T + cur.offset
	if cur.info.start == nil || t < *cur.info.start {
		v := t
		cur.info.start = &v
	}
	if cur.info.end == nil || t > *cur.info.end {
		v := t
		cur.info.end = &v
	}
	return heapItem{t: t, capIdx: cur.capIdx, frameN: rec.N, rec: rec, curIdx: cur.capIdx}, true
}

// streamIntoCorrelator merges capture cursors in timestamp order and feeds corr.
func streamIntoCorrelator(cursors []*capCursor, corr *correlator) {
	h := make(recordHeap, 0, len(cursors))
	heap.Init(&h)
	for _, cur := range cursors {
		if item, ok := cur.next(); ok {
			heap.Push(&h, item)
		}
	}
	for h.Len() > 0 {
		item := heap.Pop(&h).(heapItem)
		if item.rec.IP != nil {
			corr.feed(item.capIdx, item.t, item.rec)
		} else {
			corr.packets[item.capIdx]++
		}
		if nextItem, ok := cursors[item.curIdx].next(); ok {
			heap.Push(&h, nextItem)
		}
	}
	corr.flush()
}
