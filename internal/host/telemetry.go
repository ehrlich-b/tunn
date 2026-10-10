package host

import (
	"net/http"
	"sync/atomic"
)

// OperationalMetrics is a process-wide observation of the existing relay
// admission and audit paths, without tenant/path labels or another quota ledger.
// Embedders may export this snapshot through their own operator-only surface.
type OperationalMetrics struct {
	ActiveStreams    int64  `json:"active_streams"`
	DeniedAdmissions uint64 `json:"denied_admissions"`
	ExportDrops      uint64 `json:"export_drops"`
}
type operationalCounters struct {
	active atomic.Int64
	denied atomic.Uint64
	drops  atomic.Uint64
}

func (p *ProxyServer) OperationalMetrics() OperationalMetrics {
	return OperationalMetrics{p.operations.active.Load(), p.operations.denied.Load(), p.operations.drops.Load()}
}

// Share the relay audit ID with the publisher's connection metadata. No caller
// header supplies this value, and no credentials need to enter the inspector.
func requestConnectionID(r *http.Request) (string, error) {
	if session := meterForRequest(r); session != nil && session.event.RequestId != "" {
		return session.event.RequestId, nil
	}
	return generateConnectionID()
}
