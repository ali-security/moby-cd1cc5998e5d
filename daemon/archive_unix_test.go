//go:build linux

package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/docker/docker/container"
	"github.com/moby/go-archive"
	"github.com/moby/go-archive/compression"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// TestContainerExtractToDirDecompressesOnHost asserts the ordering property that
// fixes CVE-2026-41567 (GHSA-x86f-5xw2-fm2r): the uploaded archive is
// decompressed by the daemon on the host, before openContainerFS is called, so
// the decompression helper archive.Untar shells out to for xz and gzip streams
// can never be resolved through the container's own filesystem.
//
// Pre-fix, containerExtractToDir handed the still-compressed stream straight to
// archive.Untar from inside cfs.RunInFS, i.e. after the daemon had entered the
// container's filesystem view; a "xz" or "unpigz" binary planted in the image
// then ran as root on the host. Here the container has no RWLayer, so
// openContainerFS fails immediately: any read of the upload must therefore have
// happened before the container filesystem was ever entered.
func TestContainerExtractToDirDecompressesOnHost(t *testing.T) {
	// Keep the decompression of the gzip stream below in-process, so this test
	// does not depend on whether an unpigz binary happens to be installed.
	t.Setenv("MOBY_DISABLE_PIGZ", "1")

	content := &countingReader{Reader: bytes.NewReader(gzipped(t, singleFileTar(t, "payload.txt", "sealed")))}

	d := &Daemon{}
	ctr := &container.Container{State: container.NewState(), ID: "test-container"}

	err := d.containerExtractToDir(ctr, "/", false, false, content)

	// The extraction stopped at openContainerFS, so the container filesystem
	// was never entered...
	assert.Assert(t, err != nil, "expected openContainerFS to fail for a container without an RWLayer")
	assert.Check(t, is.ErrorContains(err, "RWLayer"), "expected the openContainerFS error, got: %v", err)

	// ...yet the upload was already being decompressed by then.
	assert.Check(t, content.reads.Load() > 0,
		"the upload was not decompressed before the container filesystem was entered")
}

// TestExtractDecompressionHelperNeverRunsInContainerFS covers the other half of
// the CVE-2026-41567 fix: the step that does run inside the container's
// filesystem view is archive.UntarUncompressed, which never executes a
// decompression helper, while the host-side compression.DecompressStream is
// what performs (and therefore what resolves the helper for) the decompression.
//
// A fake decompressor on PATH stands in for the binary an attacker plants in the
// container image: it records that it ran and emits the plaintext tar.
func TestExtractDecompressionHelperNeverRunsInContainerFS(t *testing.T) {
	tarball := singleFileTar(t, "payload.txt", "sealed")
	// Only the magic number matters: the helper is what would decompress the
	// rest, and the fake one ignores its input.
	stream := append([]byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, tarball...)

	sentinel := fakeDecompressor(t, "xz", tarball)

	t.Run("archive.Untar executes the helper found on PATH", func(t *testing.T) {
		// The pre-fix call, as a control: it proves the fake decompressor is
		// really picked up, so the assertions below are meaningful. Run from
		// inside the container filesystem view, this lookup hits the image.
		dest := t.TempDir()
		assert.NilError(t, archive.Untar(bytes.NewReader(stream), dest, &archive.TarOptions{NoLchown: true}))
		assertExtracted(t, dest, "payload.txt", "sealed")
		assert.Check(t, ranHelper(t, sentinel), "archive.Untar did not execute the decompression helper")
	})

	t.Run("archive.UntarUncompressed executes nothing", func(t *testing.T) {
		assert.NilError(t, os.RemoveAll(sentinel))

		// The post-fix in-container call. It cannot make sense of a compressed
		// stream, which is precisely why it can never execute a helper: the
		// container's filesystem is no longer a search path for one.
		dest := t.TempDir()
		err := archive.UntarUncompressed(bytes.NewReader(stream), dest, &archive.TarOptions{NoLchown: true})
		assert.Assert(t, err != nil, "a compressed stream was accepted as a tar archive")
		assert.Check(t, !ranHelper(t, sentinel), "archive.UntarUncompressed executed a decompression helper")
	})

	t.Run("decompressing on the host then untarring extracts the archive", func(t *testing.T) {
		// The full post-fix sequence of containerExtractToDir. The helper runs
		// here, in the daemon's own context on the host, and the tar that comes
		// out of it is what the in-container step unpacks.
		decompressed, err := compression.DecompressStream(bytes.NewReader(stream))
		assert.NilError(t, err)
		defer decompressed.Close()

		dest := t.TempDir()
		assert.NilError(t, archive.UntarUncompressed(decompressed, dest, &archive.TarOptions{NoLchown: true}))
		assertExtracted(t, dest, "payload.txt", "sealed")
		assert.Check(t, ranHelper(t, sentinel), "the host-side decompression did not run the helper")
	})
}

// countingReader counts how many times it was read from.
type countingReader struct {
	io.Reader
	reads atomic.Int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.reads.Add(1)
	return r.Reader.Read(p)
}

// fakeDecompressor puts an executable named name at the front of PATH which
// records that it ran, drains its stdin and writes payload to stdout. It returns
// the path of the file the fake writes when it is executed.
func fakeDecompressor(t *testing.T, name string, payload []byte) (sentinel string) {
	t.Helper()

	// Resolved before PATH is rewritten below; the fake needs it to drain its
	// stdin, which os/exec writes from a goroutine in the calling process.
	cat, err := exec.LookPath("cat")
	assert.NilError(t, err)

	dir := t.TempDir()
	sentinel = filepath.Join(dir, "executed")
	payloadPath := filepath.Join(dir, "payload.tar")
	assert.NilError(t, os.WriteFile(payloadPath, payload, 0o644))

	script := "#!/bin/sh\n" +
		": > '" + sentinel + "'\n" +
		"'" + cat + "' > /dev/null\n" +
		"'" + cat + "' '" + payloadPath + "'\n"
	bin := filepath.Join(dir, name)
	assert.NilError(t, os.WriteFile(bin, []byte(script), 0o755))

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return sentinel
}

// ranHelper reports whether the fake decompressor executed.
func ranHelper(t *testing.T, sentinel string) bool {
	t.Helper()
	_, err := os.Lstat(sentinel)
	return err == nil
}

// singleFileTar returns a tar archive holding one regular file.
func singleFileTar(t *testing.T, name, contents string) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	assert.NilError(t, tw.WriteHeader(&tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(contents)),
	}))
	_, err := tw.Write([]byte(contents))
	assert.NilError(t, err)
	assert.NilError(t, tw.Close())
	return buf.Bytes()
}

// gzipped returns data as a gzip stream.
func gzipped(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(data)
	assert.NilError(t, err)
	assert.NilError(t, gw.Close())
	return buf.Bytes()
}

// assertExtracted asserts that dest holds a file with the given contents.
func assertExtracted(t *testing.T, dest, name, contents string) {
	t.Helper()

	got, err := os.ReadFile(filepath.Join(dest, name))
	assert.NilError(t, err, "the archive was not extracted")
	assert.Check(t, is.Equal(string(got), contents))
}
