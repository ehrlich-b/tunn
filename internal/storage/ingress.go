package storage

import (
	"context"
	"time"

	"github.com/ehrlich-b/tunn/internal/store"
	internalv1 "github.com/ehrlich-b/tunn/pkg/proto/internalv1"
)

// IngressStorage extends storage without changing legacy account quota APIs.
type IngressStorage interface {
	RecordIngress(context.Context, store.IngressEvent) error
	ExportIngress(context.Context, store.IngressQuery) (*store.IngressExport, error)
}

func (s *LocalStorage) RecordIngress(ctx context.Context, e store.IngressEvent) error {
	return s.ingress.Record(ctx, e)
}
func (s *LocalStorage) ExportIngress(ctx context.Context, q store.IngressQuery) (*store.IngressExport, error) {
	return s.ingress.Export(ctx, q)
}

func (s *ProxyStorage) RecordIngress(ctx context.Context, e store.IngressEvent) error {
	client := s.getClient()
	if client == nil {
		return ErrNotAvailable
	}
	_, err := client.RecordIngress(ctx, &internalv1.RecordIngressRequest{Event: IngressEventToProto(e)})
	return err
}
func (s *ProxyStorage) ExportIngress(ctx context.Context, q store.IngressQuery) (*store.IngressExport, error) {
	client := s.getClient()
	if client == nil {
		return nil, ErrNotAvailable
	}
	resp, err := client.ExportIngress(ctx, &internalv1.ExportIngressRequest{AccountId: q.AccountID, Month: q.Month, EndpointId: q.EndpointID, After: q.After, Limit: int32(q.Limit), Counters: q.Counters})
	if err != nil {
		return nil, err
	}
	out := &store.IngressExport{Month: q.Month, NextCursor: resp.NextCursor}
	for _, e := range resp.Events {
		out.Events = append(out.Events, IngressEventFromProto(e))
	}
	for _, c := range resp.Counters {
		out.Counters = append(out.Counters, store.IngressCounter{Sequence: c.Sequence, EndpointID: c.EndpointId, CallerID: c.CallerId, AuthMethod: c.AuthMethod, Requests: c.Requests, Forwarded: c.Forwarded, Denied: c.Denied, Errors: c.Errors, RequestBytes: c.RequestBytes, ResponseBytes: c.ResponseBytes})
	}
	return out, nil
}

func IngressEventToProto(e store.IngressEvent) *internalv1.IngressEvent {
	return &internalv1.IngressEvent{Sequence: e.Sequence, RequestId: e.RequestID, AccountId: e.AccountID, EndpointId: e.EndpointID, CallerId: e.CallerID, AuthMethod: e.AuthMethod, Reason: e.Reason, Outcome: e.Outcome, Status: int32(e.Status), StartedAtUnixMs: e.StartedAt.UnixMilli(), DurationMs: e.DurationMS, Forwarded: e.Forwarded, RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes}
}
func IngressEventFromProto(e *internalv1.IngressEvent) store.IngressEvent {
	if e == nil {
		return store.IngressEvent{}
	}
	return store.IngressEvent{Sequence: e.Sequence, RequestID: e.RequestId, AccountID: e.AccountId, EndpointID: e.EndpointId, CallerID: e.CallerId, AuthMethod: e.AuthMethod, Reason: e.Reason, Outcome: e.Outcome, Status: int(e.Status), StartedAt: time.UnixMilli(e.StartedAtUnixMs).UTC(), DurationMS: e.DurationMs, Forwarded: e.Forwarded, RequestBytes: e.RequestBytes, ResponseBytes: e.ResponseBytes}
}
