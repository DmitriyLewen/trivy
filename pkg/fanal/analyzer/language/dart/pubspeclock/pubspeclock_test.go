package pubspeclock

import (
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"sort"
	"testing"
)

func Test_pubSpecLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PubSpec,
						FilePath: "testdata/happy.lock",
						Libraries: []types.Package{
							{
								ID:      "crypto@3.0.2",
								Name:    "crypto",
								Version: "3.0.2",
							},
							{
								ID:      "flutter_test@0.0.0",
								Name:    "flutter_test",
								Version: "0.0.0",
							},
							{
								ID:       "uuid@3.0.6",
								Name:     "uuid",
								Version:  "3.0.6",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name:      "empty file",
			inputFile: "testdata/empty.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := pubSpecLockAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if got != nil {
				for _, app := range got.Applications {
					sort.Slice(app.Libraries, func(i, j int) bool {
						return app.Libraries[i].ID < app.Libraries[j].ID
					})
				}
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}