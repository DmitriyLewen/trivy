package rootio

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
)

var versionSuffix = "root.io"

// RootIO matches packages patched by root.io.
// root.io provides patched versions of open source packages with their own
// vulnerability advisories. Their packages are identified by the special suffix
// in the package version (e.g., "1.2.3+root.io.1").
//
// See also: pkg/detector/ospkg/rootio/ for the OS package equivalent.
type RootIO struct{}

func (RootIO) Name() string {
	return "rootio"
}

func (RootIO) Match(eco ecosystem.Type, _, pkgVer string) bool {
	// Only support Python and Java ecosystems
	if eco != ecosystem.Pip && eco != ecosystem.Maven {
		return false
	}

	// Check if version contains root.io suffix
	return strings.Contains(pkgVer, versionSuffix)
}
