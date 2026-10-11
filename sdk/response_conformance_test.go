package tunn

import (
	"net/http"
	"testing"

	"github.com/ehrlich-b/tunn/internal/common"
	"github.com/ehrlich-b/tunn/internal/testutil/httpconformance"
)

func observation(got observedResponse) httpconformance.Observation {
	terminal := 0
	for _, frame := range got.frames {
		if frame.GetHttpResponse() != nil || frame.GetConnectionHalfClose() != nil || frame.GetConnectionClose() != nil {
			terminal++
		}
	}
	return httpconformance.Observation{Status: got.status, Header: common.DecodeHTTPResponseHeaders(got.headers, got.fields), Body: got.body, Trailer: common.DecodeHTTPResponseHeaders(nil, got.trailers), Terminals: terminal}
}

func TestHTTPFidelitySDKConformance(t *testing.T) {
	for _, scenario := range httpconformance.Scenarios() {
		reference, body := directHandlerResponse(t, http.MethodGet, scenario.Handler)
		want := httpconformance.Observation{Status: reference.StatusCode, Header: reference.Header, Body: body, Trailer: reference.Trailer, Terminals: 1}
		for _, cell := range httpconformance.Cells() {
			// Old publishers have no trailer contract. Explicit rejection by a
			// current publisher talking to an old relay has its own fidelity gate.
			if scenario.Trailers && !cell.Exact() {
				continue
			}
			t.Run(scenario.Name+"/"+cell.String(), func(t *testing.T) {
				got := observation(observeResponseCell(t, cell, http.MethodGet, scenario.Handler))
				expected := want
				if !cell.Exact() {
					expected = httpconformance.LegacyWireExpectation(want)
				}
				httpconformance.Assert(t, got, expected)
			})
		}
	}
}
