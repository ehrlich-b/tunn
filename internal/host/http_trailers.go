package host

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func validateResponseTrailers(tunnel *TunnelConnection, names []string, fields []*pb.HttpHeader) error {
	if (len(names) > 0 || len(fields) > 0) && !tunnel.Supports(common.CapabilityHTTPResponseTrailersV1) {
		return fmt.Errorf("response trailers were not negotiated")
	}
	return common.ValidateHTTPResponseTrailers(names, fields)
}

func declareResponseTrailers(header http.Header, names []string) {
	if len(names) == 0 {
		return
	}
	header.Del("Content-Length")
	for _, name := range names {
		if !strings.HasPrefix(strings.ToLower(name), "tunn-") {
			header.Add("Trailer", http.CanonicalHeaderKey(name))
		}
	}
}

func writeResponseTrailers(header http.Header, fields []*pb.HttpHeader) {
	// Reuse the same platform field and cookie boundary at terminal delivery.
	// A trailer declaration alone must not cause the fallback map to be read.
	copyApplicationResponseHeaderFields(header, nil, fields)
}
