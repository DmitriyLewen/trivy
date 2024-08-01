//go:build mage_docs

package main

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/cobra/doc"
)

const (
	title       = "Config file"
	description = "Trivy can be customized by tweaking a `trivy.yaml` file.\n" +
		"The config path can be overridden by the `--config` flag.\n\n" +
		"An example is [here][example].\n"
	footer = "[example]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/examples/trivy-conf/trivy.yaml"
)

// Generate CLI references
func main() {
	// Set a dummy path for the documents
	flag.CacheDirFlag.Default = "/path/to/cache"
	flag.ModuleDirFlag.Default = "$HOME/.trivy/modules"

	// Set a dummy path not to load plugins
	os.Setenv("XDG_DATA_HOME", os.TempDir())

	cmd := commands.NewApp()
	cmd.DisableAutoGenTag = true
	if err := doc.GenMarkdownTree(cmd, "./docs/docs/references/configuration/cli"); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}
	if err := generateConfigDocs("./docs/docs/references/configuration/config-file.md"); err != nil {
		log.Fatal("Fatal error in config file generation", log.Err(err))
	}
}

// generateConfigDocs creates markdown file for Trivy config.
func generateConfigDocs(filename string) error {
	// remoteFlags should contain Client and Server flags.
	// NewClientFlags doesn't initialize `Listen` field
	remoteFlags := flag.NewClientFlags()
	remoteFlags.Listen = flag.ServerListenFlag.Clone()

	// These flags don't work from config file.
	// Clear configName to skip them later.
	globalFlags := flag.NewGlobalFlagGroup()
	globalFlags.ConfigFile.ConfigName = ""
	globalFlags.ShowVersion.ConfigName = ""
	globalFlags.GenerateDefaultConfig.ConfigName = ""

	var allFlagGroups = []flag.FlagGroup{
		globalFlags,
		flag.NewCacheFlagGroup(),
		remoteFlags,
		flag.NewLicenseFlagGroup(),
		flag.NewK8sFlagGroup(),
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("# " + title + "\n\n")
	f.WriteString(description + "\n")

	for _, group := range allFlagGroups {
		f.WriteString("## " + group.Name() + " Options\n")
		writeFlags(group, f)
	}

	f.WriteString(footer)
	return nil
}

func writeFlags(group flag.FlagGroup, w *os.File) {
	flags := group.Flags()
	slices.SortFunc(flags, func(a, b flag.Flagger) int {
		return cmp.Compare(a.GetConfigName(), b.GetConfigName())
	})
	w.WriteString("\n```yaml\n")

	var lastParts []string
	for _, flg := range flags {
		if flg.GetConfigName() == "" {
			continue
		}
		parts := strings.Split(flg.GetConfigName(), ".") // TODO think about this name
		for i := range parts {
			// Skip already added part
			if len(lastParts) >= i+1 && parts[i] == lastParts[i] {
				continue
			}
			ind := strings.Repeat("  ", i)
			isLastPart := i == len(parts)-1
			if isLastPart {
				if flg.GetName() != "" {
					fmt.Fprintf(w, "%s# Same as '--%s'\n", ind, flg.GetName())
				}
				fmt.Fprintf(w, "%s# Default is %v\n", ind, defaultValueString(flg.GetDefaultValue()))
			}
			w.WriteString(ind + parts[i] + ": ")
			if isLastPart {
				writeFlagValue(flg.GetDefaultValue(), ind, w)
			}
			w.WriteString("\n")
		}
		lastParts = parts
	}
	w.WriteString("```\n")
}

func defaultValueString(val any) string {
	var value string
	switch v := val.(type) {
	case string:
		value = v
		if v == "" {
			value = "empty"
		}
	default:
		value = fmt.Sprintf("%v", v)
	}
	return value
}

func writeFlagValue(val any, ind string, w *os.File) {
	switch v := val.(type) {
	case string:
		w.WriteString(v + "\n")
	case []string:
		if len(v) == 0 {
			w.WriteString("[]\n")
		} else {
			w.WriteString("\n")
			for _, vv := range v {
				fmt.Fprintf(w, "%s- %s\n", ind, vv)
			}
		}
	default:
		fmt.Fprintf(w, "%v\n", v)
	}

}
