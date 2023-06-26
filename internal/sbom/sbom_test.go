package sbom

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestSBOMMetadata(t *testing.T) {
	type testData struct {
		imageName     string
		name, version string
	}
	tcs := []testData{{
		imageName: "alpine:latest",
		name:      "alpine",
		version:   "latest",
	}, {
		imageName: "debian:10",
		name:      "debian",
		version:   "10",
	}, {
		imageName: "gcr.io/distroless/static@sha256:7198a357ff3a8ef750b041324873960cf2153c11cc50abb9d8d5f8bb089f6b4e",
		name:      "gcr.io/distroless/static",
		version:   "sha256:7198a357ff3a8ef750b041324873960cf2153c11cc50abb9d8d5f8bb089f6b4e",
	}, {
		imageName: "alpine",
		name:      "alpine",
		version:   "",
	}}
	for _, tc := range tcs {
		t.Run(tc.imageName, func(t *testing.T) {
			c := &containerDepGraph{ /*don't need the depGraph Workflow*/ }
			config := configuration.New()
			config.Set("targetDirectory", tc.imageName)
			name, version, err := c.Metadata(config, nil)
			if err != nil {
				t.Fatalf("error getting metadata: %v", err)
			}
			if name != tc.name {
				t.Fatalf("name mismatch. expected=%q, got=%q", tc.name, name)
			}
			if version != tc.version {
				t.Fatalf("version mismatch. expected=%q, got=%q", tc.version, version)
			}
		})
	}
}

func TestSBOMMetadataError(t *testing.T) {
	c := &containerDepGraph{ /*don't need the depGraph Workflow*/ }
	config := configuration.New()
	config.Set("targetDirectory", ":invalid-image@name")
	_, _, err := c.Metadata(config, nil)
	if err == nil {
		t.Fatalf("expected error, but did not get one")
	}
}
