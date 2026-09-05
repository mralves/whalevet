package tarutil

import (
	"archive/tar"
	"bytes"
	"io"
	"maps"
)

// ExtractDockerfile reads a tar archive and returns the Dockerfile content,
// the dockerfile path within the archive, and all tar entries.
// When nameHint is non-empty (from the build `dockerfile` query param), that
// exact entry name takes precedence; otherwise the default Dockerfile names
// at the archive root are matched.
func ExtractDockerfile(r io.Reader, nameHint string) (dockerfilePath string, dockerfileContent string, entries []TarEntry, err error) {
	tr := tar.NewReader(r)

	isDockerfile := func(name string) bool {
		if nameHint != "" {
			return name == nameHint || name == "./"+nameHint
		}
		return name == "Dockerfile" || name == "./Dockerfile" ||
			name == "dockerfile" || name == "./dockerfile"
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", nil, err
		}

		entry := TarEntry{
			Header: *header,
		}

		if header.Typeflag == tar.TypeReg {
			content, err := io.ReadAll(tr)
			if err != nil {
				return "", "", nil, err
			}
			entry.Content = content

			if isDockerfile(header.Name) {
				dockerfilePath = header.Name
				dockerfileContent = string(content)
			}
		}

		entries = append(entries, entry)
	}

	return dockerfilePath, dockerfileContent, entries, nil
}

// TarEntry holds a tar header and its content
type TarEntry struct {
	Header  tar.Header
	Content []byte
}

// RebuildTar creates a new tar archive from entries, replacing the Dockerfile
// content. Extra files (e.g. CA certificates referenced by injected COPY
// lines) are appended at the archive root under extraFiles[name] = content.
// Existing entries with colliding names are replaced.
func RebuildTar(entries []TarEntry, dockerfilePath string, newDockerfileContent string, extraFiles map[string][]byte) io.Reader {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	remaining := maps.Clone(extraFiles)

	for _, entry := range entries {
		if entry.Header.Name == dockerfilePath {
			entry.Content = []byte(newDockerfileContent)
			entry.Header.Size = int64(len(newDockerfileContent))
		} else if content, ok := remaining[entry.Header.Name]; ok {
			entry.Content = content
			entry.Header.Size = int64(len(content))
			delete(remaining, entry.Header.Name)
		}

		if err := tw.WriteHeader(&entry.Header); err != nil {
			continue
		}

		if entry.Header.Typeflag == tar.TypeReg && len(entry.Content) > 0 {
			tw.Write(entry.Content) //nolint:gosec // content written to the tar follows the marker data path
		}
	}

	for name, content := range remaining {
		header := &tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			continue
		}
		tw.Write(content) //nolint:gosec // content written to the tar follows the marker data path
	}

	tw.Close() //nolint:gosec // the caller consumes the in-memory buffer; flush errors surface on read
	return &buf
}
