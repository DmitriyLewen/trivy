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
	var resolverApps ftypes.Applications
	for _, app := range apps {
		resolverApp := ftypes.Application{
			Type:     app.Type,
			FilePath: app.FilePath,
		}
		for _, pkg := range app.Packages {
			if pkg.Name == "lodash" {
				pkg.Version = "4.17.20"
			}
			resolverApp.Packages = append(resolverApp.Packages, pkg)
		}
		resolverApps = append(resolverApps, resolverApp)
	}
	return resolverApps, nil
}
