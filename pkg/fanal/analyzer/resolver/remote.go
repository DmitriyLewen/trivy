package resolver

import (
	"context"
	"fmt"
	"net/http"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/rpc"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
	rpcResolver "github.com/aquasecurity/trivy/rpc/resolver"
	"github.com/twitchtv/twirp"
	"golang.org/x/xerrors"
)

type RemoteOptions struct {
	ServerAddr    string
	CustomHeaders http.Header
	PathPrefix    string
}

// RemoteResolver implements remote resolver
type RemoteResolver struct {
	client rpcResolver.Resolver
}

// NewRemoteResolver is the factory method for RemoteResolver
func NewRemoteResolver(ctx context.Context, opts RemoteOptions) RemoteResolver {
	ctx = client.WithCustomHeaders(ctx, opts.CustomHeaders)

	var twirpOpts []twirp.ClientOption
	if opts.PathPrefix != "" {
		twirpOpts = append(twirpOpts, twirp.WithClientPathPrefix(opts.PathPrefix))
	}

	c := rpcResolver.NewResolverProtobufClient(opts.ServerAddr, xhttp.ClientWithContext(ctx), twirpOpts...)

	return RemoteResolver{
		client: c,
	}
}

func (r RemoteResolver) Resolve(ctx context.Context, apps ftypes.Applications) (ftypes.Applications, error) {
	fmt.Println("RemoteResolver.Resolve called")
	var res *rpcResolver.ResolveResponse
	err := rpc.Retry(func() error {
		var err error
		res, err = r.client.Resolve(ctx, rpc.ConvertToRPCResolveRequest(apps))
		if err != nil {
			return xerrors.Errorf("failed to resolve remote apps: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return rpc.ConvertFromRPCResolveResponse(res), nil
}
