package client

import (
	"fmt"
	"net/http"

	"github.com/ehrlich-b/tunn/internal/common"
	pb "github.com/ehrlich-b/tunn/pkg/proto/tunnelv1"
)

func (s *ServeClient) responseTrailerNames(response *http.Response, method string) ([]string, error) {
	if !common.HTTPResponseHasBody(method, response.StatusCode) {
		return nil, nil
	}
	names, err := common.HTTPResponseTrailerNames(response.Trailer)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 && !s.ResponseTrailers {
		return nil, fmt.Errorf("response trailers require an upgraded relay")
	}
	return names, nil
}

func (s *ServeClient) responseTrailerFields(response *http.Response, names []string) ([]*pb.HttpHeader, error) {
	_, fields := common.EncodeHTTPResponseHeaders(response.Trailer)
	if len(fields) > 0 && !s.ResponseTrailers {
		return nil, fmt.Errorf("response trailers require an upgraded relay")
	}
	if err := common.ValidateHTTPResponseTrailers(names, fields); err != nil {
		return nil, err
	}
	return fields, nil
}
