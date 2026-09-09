package image

import (
	"regexp"
	"strings"
)

type OSFamily int

const (
	OSUnknown OSFamily = iota
	OSAlpine
	OSDebian
	OSUbuntu
	OSCentOS
	OSFedora
	OSRHEL
	OSRocky
	OSAlmaLinux
	OSAmazonLinux
	OSArch
	OSOpenSUSE
	OSSLES
)

var fromPatterns = []struct {
	pattern *regexp.Regexp
	os      OSFamily
}{
	{regexp.MustCompile(`^alpine[:/]`), OSAlpine},
	{regexp.MustCompile(`^ubuntu[:/]`), OSUbuntu},
	{regexp.MustCompile(`^debian[:/]`), OSDebian},
	{regexp.MustCompile(`^centos[:/]`), OSCentOS},
	{regexp.MustCompile(`^fedora[:/]`), OSFedora},
	{regexp.MustCompile(`^rhel[:/]`), OSRHEL},
	{regexp.MustCompile(`^rocky(?:linux)?[:/]`), OSRocky},
	{regexp.MustCompile(`^almalinux[:/]`), OSAlmaLinux},
	{regexp.MustCompile(`^amazonlinux[:/]`), OSAmazonLinux},
	{regexp.MustCompile(`^archlinux[:/]`), OSArch},
	{regexp.MustCompile(`^opensuse[:/]`), OSOpenSUSE},
	{regexp.MustCompile(`^sles[:/]`), OSSLES},
}

func DetectOSFromFROM(fromLine string) OSFamily {
	// Extract image ref from FROM line: "FROM ubuntu:20.04 AS builder" -> "ubuntu:20.04"
	fields := strings.Fields(fromLine)
	if len(fields) < 2 {
		return OSUnknown
	}
	imageRef := fields[1]

	// Handle --platform flag: "FROM --platform=linux/amd64 ubuntu:20.04"
	if strings.HasPrefix(imageRef, "--") {
		if len(fields) < 3 {
			return OSUnknown
		}
		imageRef = fields[2]
	}

	// Strip digest
	if idx := strings.Index(imageRef, "@"); idx != -1 {
		imageRef = imageRef[:idx]
	}

	for _, fp := range fromPatterns {
		if fp.pattern.MatchString(imageRef) {
			return fp.os
		}
	}
	return OSUnknown
}
