package rootio

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
)

func TestRootIO_Match(t *testing.T) {
	tests := []struct {
		name    string
		eco     ecosystem.Type
		pkgName string
		pkgVer  string
		want    bool
	}{
		// Python (pip) packages with +root.io suffix in version
		{
			name:    "python package with root.io suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1+root.io.1",
			want:    true,
		},
		{
			name:    "python package without root.io suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1",
			want:    false,
		},
		{
			name:    "python package with root.io in name but not version",
			eco:     ecosystem.Pip,
			pkgName: "root.io-package",
			pkgVer:  "1.0.0",
			want:    false,
		},
		// Java (Maven) packages with root.io suffix in version
		{
			name:    "java package with root.io suffix",
			eco:     ecosystem.Maven,
			pkgName: "org.springframework:spring-core",
			pkgVer:  "5.3.20+root.io.3",
			want:    true,
		},
		{
			name:    "java package without root.io suffix",
			eco:     ecosystem.Maven,
			pkgName: "org.springframework:spring-core",
			pkgVer:  "5.3.20",
			want:    false,
		},
		// Unsupported ecosystems
		{
			name:    "node package with root.io suffix (unsupported)",
			eco:     ecosystem.Npm,
			pkgName: "express",
			pkgVer:  "4.18.0+root.io.1",
			want:    false,
		},
		// Edge cases
		{
			name:    "empty version",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := RootIO{}
			got := r.Match(tt.eco, tt.pkgName, tt.pkgVer)
			if got != tt.want {
				t.Errorf("RootIO.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRootIO_Name(t *testing.T) {
	r := RootIO{}
	got := r.Name()
	want := "rootio"
	if got != want {
		t.Errorf("RootIO.Name() = %v, want %v", got, want)
	}
}
