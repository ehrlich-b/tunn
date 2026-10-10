package consumer

import (
	"context"
	"errors"
	"net/http"
	"testing"

	tunn "github.com/ehrlich-b/tunn/sdk"
)

func TestExternalConsumer(t *testing.T) {
	// A canceled lifetime proves both entry points are callable outside the
	// module without connecting to a relay or reading local account credentials.
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	o:=tunn.Options{Origin:"http://127.0.0.1:8080",Credentials:tunn.Credentials{AuthToken:"consumer-fixture"},Reconnect:&tunn.ReconnectPolicy{MaxAttempts:0}}
	if _,err:=tunn.Publish(ctx,o);!errors.Is(err,context.Canceled){t.Fatalf("Publish: %v",err)}
	o.Origin=""
	if _,err:=tunn.PublishHandler(ctx,http.NotFoundHandler(),o);!errors.Is(err,context.Canceled){t.Fatalf("PublishHandler: %v",err)}
	var publish func(context.Context,tunn.Options)(*tunn.Tunnel,error)=tunn.Publish
	var handler func(context.Context,http.Handler,tunn.Options)(*tunn.Tunnel,error)=tunn.PublishHandler
	_,_=publish,handler
}
