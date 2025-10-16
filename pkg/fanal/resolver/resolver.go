package resolver

import (
	"context"
	"fmt"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Resolver interface {
	Resolve(ctx context.Context, apps ftypes.Applications) (ftypes.Applications, error)
}

type ApplicationsResolver struct {
}

func NewResolver(resolvers ...Resolver) Resolver {
	return ApplicationsResolver{}
}

func (ar ApplicationsResolver) Resolve(_ context.Context, apps ftypes.Applications) (ftypes.Applications, error) {
	fmt.Println("ApplicationsResolver.Resolve called")
	return apps, nil
}
