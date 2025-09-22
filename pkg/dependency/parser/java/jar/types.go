package jar

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var ArtifactNotFoundErr = xerrors.New("no artifact found")

type Properties struct {
	GroupID    string
	ArtifactID string
	Version    string
	FilePath   string        // path to file containing these props
	Digest     digest.Digest // SHA1 digest of the file
}

func (p Properties) Package(withID bool) ftypes.Package {
	name := fmt.Sprintf("%s:%s", p.GroupID, p.ArtifactID)
	return ftypes.Package{
		ID:       lo.Ternary(withID, dependency.ID(ftypes.Jar, name, p.Version), ""),
		Name:     name,
		Version:  p.Version,
		FilePath: p.FilePath,
		Digest:   p.Digest,
	}
}

func (p Properties) Valid() bool {
	return p.GroupID != "" && p.ArtifactID != "" && p.Version != ""
}

func (p Properties) String() string {
	return fmt.Sprintf("%s:%s:%s", p.GroupID, p.ArtifactID, p.Version)
}
