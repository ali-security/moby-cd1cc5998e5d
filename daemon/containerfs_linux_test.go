//go:build linux

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestCreateIfNotExists(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()

		err := createIfNotExists(dir, "tocreate", true)
		assert.NilError(t, err)

		fileinfo, err := os.Stat(filepath.Join(dir, "tocreate"))
		assert.NilError(t, err, "Did not create destination")
		assert.Assert(t, fileinfo.IsDir(), "Should have been a dir, seems it's not")

		err = createIfNotExists(dir, "tocreate", true)
		assert.NilError(t, err, "Should not fail if already exists")
	})
	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()

		err := createIfNotExists(dir, filepath.Join("file", "to", "create"), false)
		assert.NilError(t, err)

		fileinfo, err := os.Stat(filepath.Join(dir, "file", "to", "create"))
		assert.NilError(t, err, "Did not create destination")

		assert.Assert(t, !fileinfo.IsDir(), "Should have been a file, but created a directory")

		err = createIfNotExists(dir, filepath.Join("file", "to", "create"), false)
		assert.NilError(t, err, "Should not fail if already exists")
	})
	t.Run("dangling in-root symlink at the destination is followed", func(t *testing.T) {
		// This is the shape of the network mounts openContainerFS creates for
		// every container: /etc/resolv.conf, /etc/hosts and /etc/hostname are
		// file mounts, and images derived from systemd-based distros ship
		// /etc/resolv.conf as a relative symlink into /run whose target does
		// not exist yet. The destination must be followed to that in-root
		// target rather than rejected, or every such container breaks.
		root := t.TempDir()
		assert.NilError(t, os.Mkdir(filepath.Join(root, "etc"), 0o755))
		assert.NilError(t, os.Mkdir(filepath.Join(root, "run"), 0o755))

		// etc/resolv.conf -> ../run/resolv.conf, a dangling symlink whose
		// target's parent exists.
		link := filepath.Join(root, "etc", "resolv.conf")
		target := filepath.Join(root, "run", "resolv.conf")
		assert.NilError(t, os.Symlink(filepath.Join("..", "run", "resolv.conf"), link))

		err := createIfNotExists(root, filepath.Join("etc", "resolv.conf"), false)
		assert.NilError(t, err, "in-root symlink at the destination was not followed")

		// The symlink target is what got created...
		targetInfo, err := os.Lstat(target)
		assert.NilError(t, err, "the symlink target was not created")
		assert.Check(t, targetInfo.Mode().IsRegular(),
			"expected a regular file at the symlink target, got %s", targetInfo.Mode())

		// ...and the symlink itself was left alone rather than being replaced
		// by a regular file.
		linkInfo, err := os.Lstat(link)
		assert.NilError(t, err)
		assert.Check(t, linkInfo.Mode()&os.ModeSymlink != 0,
			"the symlink was replaced by %s", linkInfo.Mode())

		// Now that the target exists, this must be a no-op.
		err = createIfNotExists(root, filepath.Join("etc", "resolv.conf"), false)
		assert.NilError(t, err, "Should not fail if already exists")
	})
	t.Run("in-root symlink to an existing node is a no-op", func(t *testing.T) {
		// The destination already resolves, through an in-root symlink, to a
		// node of the right type: nothing may be created or replaced.
		for _, tc := range []struct {
			name  string
			isDir bool
		}{
			{name: "file", isDir: false},
			{name: "directory", isDir: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				root := t.TempDir()
				assert.NilError(t, os.Mkdir(filepath.Join(root, "etc"), 0o755))
				assert.NilError(t, os.Mkdir(filepath.Join(root, "run"), 0o755))

				target := filepath.Join(root, "run", "target")
				if tc.isDir {
					assert.NilError(t, os.Mkdir(target, 0o755))
				} else {
					assert.NilError(t, os.WriteFile(target, []byte("keep me"), 0o644))
				}

				link := filepath.Join(root, "etc", "link")
				assert.NilError(t, os.Symlink(filepath.Join("..", "run", "target"), link))

				err := createIfNotExists(root, filepath.Join("etc", "link"), tc.isDir)
				assert.NilError(t, err, "in-root symlink to an existing node was rejected")

				// The symlink is untouched...
				linkInfo, err := os.Lstat(link)
				assert.NilError(t, err)
				assert.Check(t, linkInfo.Mode()&os.ModeSymlink != 0,
					"the symlink was replaced by %s", linkInfo.Mode())

				// ...and so is its target.
				targetInfo, err := os.Lstat(target)
				assert.NilError(t, err)
				assert.Check(t, is.Equal(targetInfo.IsDir(), tc.isDir),
					"the symlink target changed type")
				if !tc.isDir {
					content, err := os.ReadFile(target)
					assert.NilError(t, err)
					assert.Check(t, is.Equal(string(content), "keep me"),
						"the existing file was truncated")
				}
			})
		}
	})
	t.Run("symlinked leaf pointing out of the root is clamped to it", func(t *testing.T) {
		// A symlink planted at the destination leaf by a malicious
		// container image is resolved relative to the container root, so
		// the node is created inside the root and nothing whatsoever is
		// created (or opened) on the host outside of it.
		root, outside := scratchRootAndOutside(t)
		// The in-root mirror of the host path the symlink points at, which
		// is the furthest the resolution can ever reach.
		mirrored := filepath.Join(root, outside)
		assert.NilError(t, os.MkdirAll(mirrored, 0o755))

		evil := filepath.Join(root, "evil")
		assert.NilError(t, os.Symlink(filepath.Join(outside, "pwned"), evil))

		assert.NilError(t, createIfNotExists(root, "evil", false))

		// Nothing was created outside the root; in particular the symlink
		// target on the host does not exist.
		assertEmptyDir(t, outside)
		_, err := os.Lstat(filepath.Join(outside, "pwned"))
		assert.Check(t, os.IsNotExist(err), "created an entry outside the root: %v", err)

		// The creation landed at the root-relative version of the target.
		_, err = os.Lstat(filepath.Join(mirrored, "pwned"))
		assert.NilError(t, err, "should have been created inside the root")

		// The symlink itself was not replaced by a regular file.
		linkInfo, err := os.Lstat(evil)
		assert.NilError(t, err)
		assert.Check(t, linkInfo.Mode()&os.ModeSymlink != 0,
			"the symlink was replaced by %s", linkInfo.Mode())
	})
	t.Run("symlinked leaf whose in-root target parent is missing fails", func(t *testing.T) {
		// When the destination is a symlink whose resolved target lives
		// under directories which do not exist, the creation fails rather
		// than reaching outside the root: only the destination's own parent
		// directories are created, never the symlink target's.
		root, outside := scratchRootAndOutside(t)

		assert.NilError(t, os.Symlink(filepath.Join(outside, "pwned"), filepath.Join(root, "evil")))

		err := createIfNotExists(root, "evil", false)
		assert.Assert(t, err != nil, "expected an error, nothing should have been created")
		assert.Check(t, errors.Is(err, os.ErrNotExist), "expected a not-exist error, got: %v", err)

		assertEmptyDir(t, outside)
		_, err = os.Lstat(filepath.Join(outside, "pwned"))
		assert.Check(t, os.IsNotExist(err), "created an entry outside the root: %v", err)
	})
	t.Run("absolute symlink at the destination cannot escape the root", func(t *testing.T) {
		// An absolute symlink inside the container filesystem must be
		// resolved relative to the container root, not to the host root,
		// so the furthest it can ever reach is <root>/<outside>.
		root, outside := scratchRootAndOutside(t)
		mirrored := filepath.Join(root, outside)
		assert.NilError(t, os.MkdirAll(mirrored, 0o755))

		assert.NilError(t, os.Symlink(outside, filepath.Join(root, "link")))

		// Both the directory and the file flavour must stay inside root.
		assert.NilError(t, createIfNotExists(root, filepath.Join("link", "dir"), true))
		assert.NilError(t, createIfNotExists(root, filepath.Join("link", "file"), false))

		_, err := os.Stat(filepath.Join(mirrored, "dir"))
		assert.NilError(t, err, "should have been created inside the root")
		_, err = os.Stat(filepath.Join(mirrored, "file"))
		assert.NilError(t, err, "should have been created inside the root")

		assertEmptyDir(t, outside)
	})
	t.Run("parent traversal is clamped to root", func(t *testing.T) {
		root, outside := scratchRootAndOutside(t)

		assert.NilError(t, createIfNotExists(root, filepath.Join("..", "..", "pwned-dir"), true))
		assert.NilError(t, createIfNotExists(root, filepath.Join("..", "..", "pwned-file"), false))

		_, err := os.Stat(filepath.Join(root, "pwned-dir"))
		assert.NilError(t, err, "traversal should have been clamped inside the root")
		_, err = os.Stat(filepath.Join(root, "pwned-file"))
		assert.NilError(t, err, "traversal should have been clamped inside the root")

		assertEmptyDir(t, outside)
		// Nothing may be created next to the root either.
		_, err = os.Lstat(filepath.Join(filepath.Dir(root), "pwned-dir"))
		assert.Check(t, os.IsNotExist(err), "created an entry outside the root: %v", err)
		_, err = os.Lstat(filepath.Join(filepath.Dir(root), "pwned-file"))
		assert.Check(t, os.IsNotExist(err), "created an entry outside the root: %v", err)
	})
}

func TestOpenMountTarget(t *testing.T) {
	t.Run("resolves within root", func(t *testing.T) {
		root := t.TempDir()
		assert.NilError(t, os.Mkdir(filepath.Join(root, "dest"), 0o755))

		f, targetPath, err := openMountTarget(root, "dest")
		assert.NilError(t, err)
		defer f.Close()

		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)

		want, err := os.Stat(filepath.Join(root, "dest"))
		assert.NilError(t, err)
		got, err := os.Stat(resolved)
		assert.NilError(t, err)
		assert.Check(t, os.SameFile(want, got), "fd does not refer to the in-root destination")
	})
	t.Run("absolute symlink at the destination cannot escape the root", func(t *testing.T) {
		root, outside := scratchRootAndOutside(t)
		// An absolute symlink is resolved relative to the root, so the
		// path it can ever reach is <root>/<outside>, not <outside>.
		mirrored := filepath.Join(root, outside)
		assert.NilError(t, os.MkdirAll(mirrored, 0o755))
		assert.NilError(t, os.Symlink(outside, filepath.Join(root, "dest")))

		f, targetPath, err := openMountTarget(root, "dest")
		assert.NilError(t, err)
		defer f.Close()

		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)

		inRoot, err := os.Stat(mirrored)
		assert.NilError(t, err)
		got, err := os.Stat(resolved)
		assert.NilError(t, err)
		assert.Check(t, os.SameFile(inRoot, got), "fd escaped the root, resolved to %q", resolved)

		hostDir, err := os.Stat(outside)
		assert.NilError(t, err)
		assert.Check(t, !os.SameFile(hostDir, got), "fd resolved to the host directory %q", outside)
	})
	t.Run("parent traversal is clamped to root", func(t *testing.T) {
		root, _ := scratchRootAndOutside(t)
		assert.NilError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))

		f, targetPath, err := openMountTarget(root, filepath.Join("a", "b", "..", "..", "..", ".."))
		assert.NilError(t, err)
		defer f.Close()

		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)

		rootInfo, err := os.Stat(root)
		assert.NilError(t, err)
		got, err := os.Stat(resolved)
		assert.NilError(t, err)
		assert.Check(t, os.SameFile(rootInfo, got), "traversal escaped the root, resolved to %q", resolved)
	})
	t.Run("fd pins the destination against a symlink swap", func(t *testing.T) {
		// This is the vulnerability: between resolving the mount
		// destination by name and mounting onto it, a process inside the
		// container can swap the destination for a symlink pointing at a
		// host path. Using the fd as the mount target defeats that.
		root, outside := scratchRootAndOutside(t)
		dest := filepath.Join(root, "dest")
		assert.NilError(t, os.Mkdir(dest, 0o755))

		f, targetPath, err := openMountTarget(root, "dest")
		assert.NilError(t, err)
		defer f.Close()

		// Perform the swap after the destination has been resolved.
		assert.NilError(t, os.Rename(dest, filepath.Join(root, "stashed")))
		assert.NilError(t, os.Symlink(outside, dest))

		// By-name resolution (the pre-fix behaviour) now lands on the
		// host directory...
		byName, err := filepath.EvalSymlinks(dest)
		assert.NilError(t, err)
		hostDir, err := os.Stat(outside)
		assert.NilError(t, err)
		byNameInfo, err := os.Stat(byName)
		assert.NilError(t, err)
		assert.Check(t, os.SameFile(hostDir, byNameInfo),
			"test setup is not reproducing the swap: %q did not resolve to %q", dest, outside)

		// ...while the fd-pinned target still refers to the original
		// in-root inode, which is what gets mounted onto.
		resolved, err := os.Readlink(targetPath)
		assert.NilError(t, err)
		pinned, err := os.Stat(resolved)
		assert.NilError(t, err)
		stashed, err := os.Stat(filepath.Join(root, "stashed"))
		assert.NilError(t, err)
		assert.Check(t, os.SameFile(stashed, pinned),
			"mount target followed the symlink swap, resolved to %q", resolved)
		assert.Check(t, !os.SameFile(hostDir, pinned),
			"mount target was redirected to the host path %q", outside)
	})
}

// outsideBaseName is the base name of the out-of-root scratch directory created
// by scratchRootAndOutside. It doubles as the path an absolute in-container
// symlink to that directory resolves to once scoped to the root.
const outsideBaseName = "outside"

// scratchRootAndOutside returns a directory to be used as a container root and
// a sibling directory that stands in for a sensitive host location outside of
// that root.
func scratchRootAndOutside(t *testing.T) (root string, outside string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "root")
	outside = filepath.Join(base, outsideBaseName)
	assert.NilError(t, os.Mkdir(root, 0o755))
	assert.NilError(t, os.Mkdir(outside, 0o755))
	return root, outside
}

// assertEmptyDir asserts that nothing was created in dir.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	assert.NilError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Check(t, is.Len(names, 0), "entries were created outside the root: %v", names)
}
