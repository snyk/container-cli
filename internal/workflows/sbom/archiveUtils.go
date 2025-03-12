package sbom

import (
	"path"
	"strings"
)

type ImageType int

const (
	DockerArchive ImageType = iota
	OciArchive
	Identifier
)

// Ported from https://github.com/snyk/snyk-docker-plugin/blob/b24ef0016347a98338535915ce5fc319e45c55e8/lib/image-type.ts#L4-L16
func GetImageType(targetImage string) ImageType {
	imageIdentifier := strings.Split(targetImage, ":")[0]
	switch imageIdentifier {
	case "docker-archive":
		return DockerArchive
	case "oci-archive":
		return OciArchive
	default:
		return Identifier
	}
}

// Ported from https://github.com/snyk/snyk-docker-plugin/blob/b24ef0016347a98338535915ce5fc319e45c55e8/lib/dependency-tree/index.ts#L15-L42
func GetImageAndVersionFromFilePath(targetImage string) (string, string) {
	targetImage = path.Base(targetImage)
	imageName := targetImage
	imageVersion := "latest"

	finalSlash := strings.LastIndex(targetImage, "/")
	hasVersion := (finalSlash >= 0 && strings.Contains(targetImage[finalSlash:], ":")) || strings.Contains(targetImage, ":")

	if hasVersion {
		versionSeparator := strings.LastIndex(targetImage, ":")
		imageName = targetImage[:versionSeparator]
		imageVersion = targetImage[versionSeparator+1:]
	}

	if strings.HasSuffix(imageVersion, ".tar") {
		imageVersion = strings.TrimSuffix(imageVersion, ".tar")
	}

	shaString := "@sha256"

	if strings.HasSuffix(imageName, shaString) {
		imageName = imageName[:len(imageName)-len(shaString)]
		imageVersion = ""
	}

	return imageName, imageVersion
}
