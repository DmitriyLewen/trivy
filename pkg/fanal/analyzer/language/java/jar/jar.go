package jar

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/log"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJar, newJavaLibraryAnalyzer)
}

const version = 1

var ArtifactNotFoundErr = xerrors.New("no artifact found")

var requiredExtensions = []string{
	".jar",
	".war",
	".ear",
	".par",
}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct {
	parallel  int
	useClient bool
	logger    *log.Logger
}

func newJavaLibraryAnalyzer(options analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaLibraryAnalyzer{
		parallel:  options.Parallel,
		useClient: true,
		logger:    log.WithPrefix("jar"),
	}, nil
}

func (a *javaLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// TODO: think about the sonatype API and "--offline"
	var client *javadb.DB
	var err error
	if a.useClient {
		client, err = javadb.NewClient()
		if err != nil {
			return nil, xerrors.Errorf("Unable to initialize the Java DB: %s", err)
		}
		defer func() { _ = client.Close() }()

		// Skip analyzing JAR files as the nil client means the Java DB was not downloaded successfully.
		if client == nil {
			return nil, nil
		}
	}

	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		p := jar.NewParser(client, jar.WithSize(info.Size()), jar.WithFilePath(path))
		return language.ParsePackage(types.Jar, path, r, p, false)
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app == nil {
			return nil
		}
		pkgs, err := a.UpdatePkgs(app.Packages, client)
		if err != nil {
			return xerrors.Errorf("unable to update packages: %w", err)
		}
		app.Packages = pkgs
		apps = append(apps, *app)
		return nil
	}

	if err = parallel.WalkDir(ctx, input.FS, ".", a.parallel, onFile, onResult); err != nil {
		return nil, xerrors.Errorf("walk dir error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a *javaLibraryAnalyzer) UpdatePkgs(pkgs types.Packages, client *javadb.DB) (types.Packages, error) {
	var updatedPkgs types.Packages
	for _, pkg := range pkgs {
		// Packages obtained from `pom.properties` have pkg.ID.
		// They don’t need to be checked with the Java DB client, as they are already valid.
		if pkg.ID != "" {
			updatedPkgs = append(updatedPkgs, pkg)
			continue
		}
		// If the Java DB client is not available, retain only valid (groupID:artifactID:version) package obtained from MANIFEST.MF.
		// In this case, we don’t verify whether the package (groupID + artifactID) exists in Maven Central.
		if client == nil {
			if validPkgName(pkg.Name) {
				pkg.ID = packageID(pkg)
				updatedPkgs = append(updatedPkgs, pkg)
			}
			continue
		}

		p, err := a.processPkgWithClient(pkg, client)
		// TODO error or skip???
		if err != nil {
			return nil, xerrors.Errorf("unable to process package %s: %w", pkg.Name, err)
		}
		p.ID = packageID(p)
		updatedPkgs = append(updatedPkgs, p)
	}

	return updatedPkgs, nil
}

func (a *javaLibraryAnalyzer) processPkgWithClient(pkg types.Package, client *javadb.DB) (types.Package, error) {
	groupID, artifactID, validName := strings.Cut(pkg.Name, ":")
	if !validName {
		return types.Package{}, xerrors.Errorf("invalid package name: %s", pkg.Name)
	}

	// This package obtain from `MANIFEST.MF`.
	// We need to verify GroupID and ArtifactID via the Java DB client.
	if groupID != "" {
		// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
		// We have to make sure that the artifact exists actually.
		if ok, _ := client.Exists(groupID, artifactID); ok {
			// If groupId and artifactId are valid, they will be returned.
			return pkg, nil
		}
	}

	props, err := client.SearchBySHA1(pkg.Digest.Encoded())
	if err == nil {
		p := props.Package(true)
		p.FilePath = pkg.FilePath
		p.Digest = pkg.Digest
		return p, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return types.Package{}, xerrors.Errorf("failed to search by SHA1: %w", err)
	}

	a.logger.Debug("No such package in the central repositories", log.String("name", pkg.Name), log.String("version", pkg.Version))

	// Return when artifactId or version are empty (should be filled from file name)
	if artifactID == "" || pkg.Version == "" {
		return types.Package{}, nil
	}

	// Try to search groupId by artifactId via client
	// When some artifacts have the same groupIds, it might result in false detection.
	groupID, err = client.SearchByArtifactID(artifactID, pkg.Version)
	if err == nil {
		a.logger.Debug("POM was determined in a heuristic way", log.String("name", pkg.Name), log.String("version", pkg.Version))
		pkg.Name = groupID + ":" + artifactID
		return pkg, nil
	} else if !errors.Is(err, ArtifactNotFoundErr) {
		return types.Package{}, xerrors.Errorf("failed to search by artifact id: %w", err)
	}

	// Skip package if we couldn't determine it using the client.
	return types.Package{}, nil
}

func validPkgName(name string) bool {
	g, a, ok := strings.Cut(name, ":")
	return ok && g != "" && a != ""
}

func (a *javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a *javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a *javaLibraryAnalyzer) Version() int {
	return version
}

func packageID(pkg types.Package) string {
	return dependency.ID(types.Jar, pkg.Name, pkg.Version)
}
