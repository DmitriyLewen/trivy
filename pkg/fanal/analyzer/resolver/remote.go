package resolver

import (
	"context"
	"fmt"
	"net/http"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/twitchtv/twirp"
)

type RemoteOptions struct {
	ServerAddr    string
	CustomHeaders http.Header
	PathPrefix    string
}

// RemoteResolver implements remote resolver
type RemoteResolver struct {
	client Resolver
}

// NewRemoteResolver is the factory method for RemoteResolver
func NewRemoteResolver(ctx context.Context, opts RemoteOptions) RemoteResolver {
	ctx = client.WithCustomHeaders(ctx, opts.CustomHeaders)

	var twirpOpts []twirp.ClientOption
	if opts.PathPrefix != "" {
		twirpOpts = append(twirpOpts, twirp.WithClientPathPrefix(opts.PathPrefix))
	}
	//c := rpcCache.NewCacheProtobufClient(opts.ServerAddr, xhttp.ClientWithContext(ctx), twirpOpts...)
	return RemoteResolver{}
}

func (r RemoteResolver) Resolve(ctx context.Context, apps ftypes.Applications) (ftypes.Applications, error) {
	fmt.Println("RemoteResolver.Resolve called")
	return apps, nil
}
