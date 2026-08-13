package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/containerd/log"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/hashicorp/go-multierror"
	"github.com/moby/sys/mount"
	"github.com/moby/sys/symlink"
	"golang.org/x/sys/unix"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	"github.com/docker/docker/internal/mounttree"
	"github.com/docker/docker/internal/unshare"
)

type future struct {
	fn  func() error
	res chan<- error
}

// containerFSView allows functions to be run in the context of a container's
// filesystem. Inside these functions, the root directory is the container root
// for all native OS filesystem APIs, including, but not limited to, the [os]
// and [golang.org/x/sys/unix] packages. The view of the container's filesystem
// is live and read-write. Each view has its own private set of tmpfs mounts.
// Any files written under a tmpfs mount are not visible to processes inside the
// container nor any other view of the container's filesystem, and vice versa.
//
// Each view has its own current working directory which is initialized to the
// root of the container filesystem and can be changed with [os.Chdir]. Changes
// to the current directory persist across successive [*containerFSView.RunInFS]
// and [*containerFSView.GoInFS] calls.
//
// Multiple views of the same container filesystem can coexist at the same time.
// Only one function can be running in a particular filesystem view at any given
// time. Calls to [*containerFSView.RunInFS] or [*containerFSView.GoInFS] will
// block while another function is running. If more than one call is blocked
// concurrently, the order they are unblocked is undefined.
type containerFSView struct {
	d    *Daemon
	ctr  *container.Container
	todo chan future
	done chan error
}

// openContainerFS opens a new view of the container's filesystem.
func (daemon *Daemon) openContainerFS(ctr *container.Container) (_ *containerFSView, retErr error) {
	ctx := context.TODO()

	if err := daemon.Mount(ctr); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if err := daemon.Unmount(ctr); err != nil {
				log.G(ctx).WithError(err).Debug("Failed to unmount container after failure")
			}
		}
	}()

	mounts, cleanup, err := daemon.setupMounts(ctx, ctr)
	if err != nil {
		return nil, err
	}
	defer func() {
		ctx := context.WithoutCancel(ctx)
		if err := cleanup(ctx); err != nil {
			log.G(ctx).WithError(err).Debug("Failed to cleanup container mounts")
		}
		if retErr != nil {
			if err := ctr.UnmountVolumes(ctx, daemon.LogVolumeEvent); err != nil {
				log.G(ctx).WithError(err).Debug("Failed to unmount container volumes after failure")
			}
		}
	}()

	// Setup in initial mount namespace complete. We're ready to unshare the
	// mount namespace and bind the volume mounts into that private view of
	// the container FS.
	todo := make(chan future)
	done := make(chan error)
	err = unshare.Go(unix.CLONE_NEWNS,
		func() error {
			if err := mount.MakeRSlave("/"); err != nil {
				return err
			}
			for _, m := range mounts {
				// Destination is an absolute path within the container
				// filesystem. Make it relative to the container root so it can
				// be resolved safely (scoped) against ctr.BaseFS.
				relDest, err := filepath.Rel("/", m.Destination)
				if err != nil {
					return fmt.Errorf("make destination relative: %w", err)
				}

				var stat os.FileInfo
				stat, err = os.Stat(m.Source)
				if err != nil {
					return err
				}
				if err := createIfNotExists(ctr.BaseFS, relDest, stat.IsDir()); err != nil {
					return err
				}

				bindMode := "rbind"
				if m.NonRecursive {
					bindMode = "bind"
				}
				if m.Writable {
					if m.ReadOnlyNonRecursive {
						return errors.New("options conflict: Writable && ReadOnlyNonRecursive")
					}
					if m.ReadOnlyForceRecursive {
						return errors.New("options conflict: Writable && ReadOnlyForceRecursive")
					}
				}
				if m.ReadOnlyNonRecursive && m.ReadOnlyForceRecursive {
					return errors.New("options conflict: ReadOnlyNonRecursive && ReadOnlyForceRecursive")
				}

				// Pin the resolved mount destination with a file descriptor and
				// mount onto /proc/self/fd/<fd>, so that a symlink swap racing
				// the resolution cannot redirect the bind mount (TOCTOU).
				targetFile, targetPath, err := openMountTarget(ctr.BaseFS, relDest)
				if err != nil {
					return fmt.Errorf("open mount target %q: %w", m.Destination, err)
				}

				// The kernel rejects remount and propagation-change syscalls
				// when the target is a /proc/self/fd path. Only the initial
				// bind mount works on such paths, so we perform that via the fd
				// path for TOCTOU safety and then resolve the real path for the
				// read-only remount and propagation change.
				if err := mount.Mount(m.Source, targetPath, "", bindMode); err != nil {
					targetFile.Close()
					return err
				}
				realPath, err := os.Readlink(targetPath)
				if err != nil {
					targetFile.Close()
					return fmt.Errorf("readlink %s: %w", targetPath, err)
				}
				if !m.Writable {
					if err := mount.Mount("", realPath, "", "ro,remount,bind"); err != nil {
						targetFile.Close()
						return err
					}
				}

				// openContainerFS() is called for temporary mounts
				// outside the container. Soon these will be unmounted
				// with lazy unmount option and given we have mounted
				// them rbind, all the submounts will propagate if these
				// are shared. If daemon is running in host namespace
				// and has / as shared then these unmounts will
				// propagate and unmount original mount as well. So make
				// all these mounts rprivate.  Do not use propagation
				// property of volume as that should apply only when
				// mounting happens inside the container.
				if err := mount.MakeRPrivate(realPath); err != nil {
					targetFile.Close()
					return err
				}

				if !m.Writable && !m.ReadOnlyNonRecursive {
					if err := makeMountRRO(realPath); err != nil {
						targetFile.Close()
						if m.ReadOnlyForceRecursive {
							return err
						}
						log.G(context.Background()).WithError(err).Debugf("Failed to make %q recursively read-only", m.Destination)
					}
				}
				targetFile.Close()
			}

			return mounttree.SwitchRoot(ctr.BaseFS)
		},
		func() {
			defer close(done)

			for it := range todo {
				err := it.fn()
				if it.res != nil {
					it.res <- err
				}
			}

			// The thread will terminate when this goroutine returns, taking the
			// mount namespace and all the volume bind-mounts with it.
		},
	)
	if err != nil {
		return nil, err
	}
	vw := &containerFSView{
		d:    daemon,
		ctr:  ctr,
		todo: todo,
		done: done,
	}
	runtime.SetFinalizer(vw, (*containerFSView).Close)
	return vw, nil
}

// RunInFS synchronously runs fn in the context of the container filesystem and
// passes through its return value.
//
// The container filesystem is only visible to functions called in the same
// goroutine as fn. Goroutines started from fn will see the host's filesystem.
func (vw *containerFSView) RunInFS(ctx context.Context, fn func() error) error {
	res := make(chan error)
	select {
	case vw.todo <- future{fn: fn, res: res}:
	case <-ctx.Done():
		return ctx.Err()
	}
	return <-res
}

// GoInFS starts fn in the container FS. It blocks until fn is started but does
// not wait until fn returns. An error is returned if ctx is canceled before fn
// has been started.
//
// The container filesystem is only visible to functions called in the same
// goroutine as fn. Goroutines started from fn will see the host's filesystem.
func (vw *containerFSView) GoInFS(ctx context.Context, fn func()) error {
	select {
	case vw.todo <- future{fn: func() error { fn(); return nil }}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close waits until any in-flight operations complete and frees all
// resources associated with vw.
func (vw *containerFSView) Close() error {
	runtime.SetFinalizer(vw, nil)
	close(vw.todo)
	err := multierror.Append(nil, <-vw.done)
	err = multierror.Append(err, vw.ctr.UnmountVolumes(context.TODO(), vw.d.LogVolumeEvent))
	err = multierror.Append(err, vw.d.Unmount(vw.ctr))
	return err.ErrorOrNil()
}

// Stat returns the metadata for path, relative to the current working directory
// of vw inside the container filesystem view.
func (vw *containerFSView) Stat(ctx context.Context, path string) (*containertypes.PathStat, error) {
	var stat *containertypes.PathStat
	err := vw.RunInFS(ctx, func() error {
		lstat, err := os.Lstat(path)
		if err != nil {
			return err
		}
		var target string
		if lstat.Mode()&os.ModeSymlink != 0 {
			// Fully evaluate symlinks along path to the ultimate
			// target, or as much as possible with broken links.
			target, err = symlink.FollowSymlinkInScope(path, "/")
			if err != nil {
				return err
			}
		}
		stat = &containertypes.PathStat{
			Name:       filepath.Base(path),
			Size:       lstat.Size(),
			Mode:       lstat.Mode(),
			Mtime:      lstat.ModTime(),
			LinkTarget: target,
		}
		return nil
	})
	return stat, err
}

// createIfNotExists creates a file or a directory only if it does not already
// exist. unsafePath is interpreted relative to rootPath, and every filesystem
// operation is scoped to rootPath, so that symlinks (including ones planted by
// a malicious container image) cannot cause anything to be created outside of
// rootPath. Symlinks which resolve inside rootPath are followed, just as the
// container itself resolves them; a symlink which would leave rootPath is
// resolved relative to rootPath instead, as if the container root were "/".
func createIfNotExists(rootPath, unsafePath string, isDir bool) error {
	// If the path already resolves to an existing node inside the root there is
	// nothing to create. The lookup is scoped to rootPath but follows symlinks
	// which stay inside it, so a destination which is a symlink to another
	// location in the container filesystem (as /etc/resolv.conf commonly is)
	// keeps working.
	if f, err := securejoin.OpenInRoot(rootPath, unsafePath); err == nil {
		return f.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		// Anything other than a missing path (a non-directory path component,
		// a symlink loop, ...) is reported instead of silently creating
		// something in an unexpected place.
		return err
	}

	if isDir {
		return securejoin.MkdirAll(rootPath, unsafePath, 0o755)
	}

	parent := filepath.Dir(unsafePath)
	if parent != "." && parent != string(filepath.Separator) {
		if err := securejoin.MkdirAll(rootPath, parent, 0o755); err != nil {
			return err
		}
	}

	// The path does not exist yet. Resolve it within the root, so that symlink
	// components -- including a symlink at the final component which points at
	// a path that does not exist yet, such as the /etc/resolv.conf links into
	// /run that many images ship -- are followed just as the container resolves
	// them, while a component which would leave the root is resolved relative
	// to the root instead.
	//
	// The resolved path is only a candidate: everything below re-resolves it
	// through the root-scoped, race-safe securejoin primitives, so even if the
	// container mutates the filesystem concurrently nothing can be created
	// outside of rootPath. Only the destination's own parent directories are
	// created above, never those of a symlink target, so a symlink pointing
	// into a directory which does not exist fails rather than materialising it.
	resolvedPath, err := securejoin.SecureJoin(rootPath, unsafePath)
	if err != nil {
		return err
	}
	relPath, err := filepath.Rel(filepath.Clean(rootPath), resolvedPath)
	if err != nil {
		return err
	}

	// Resolve the parent directory within the root and create the final
	// component relative to that directory handle. relPath is already fully
	// resolved, so O_NOFOLLOW only rejects a symlink planted at the final
	// component after it was resolved -- a race we want to refuse rather than
	// follow.
	parentFd, err := securejoin.OpenInRoot(rootPath, filepath.Dir(relPath))
	if err != nil {
		return err
	}
	defer parentFd.Close()

	fd, err := unix.Openat(int(parentFd.Fd()), filepath.Base(relPath), unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o755)
	if err != nil {
		return &os.PathError{Op: "openat", Path: unsafePath, Err: err}
	}
	return unix.Close(fd)
}

// openMountTarget resolves unsafePath scoped to rootPath and returns a handle
// pinning the resolved inode along with a /proc/self/fd path referring to it.
// Using that path as a mount target prevents a subsequent symlink swap from
// redirecting the mount somewhere else.
func openMountTarget(rootPath, unsafePath string) (*os.File, string, error) {
	f, err := securejoin.OpenInRoot(rootPath, unsafePath)
	if err != nil {
		return nil, "", err
	}
	return f, "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10), nil
}

// makeMountRRO makes the mount recursively read-only.
func makeMountRRO(dest string) error {
	attr := &unix.MountAttr{
		Attr_set: unix.MOUNT_ATTR_RDONLY,
	}
	var err error
	for {
		err = unix.MountSetattr(-1, dest, unix.AT_RECURSIVE, attr)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		err = fmt.Errorf("failed to apply MOUNT_ATTR_RDONLY with AT_RECURSIVE to %q: %w", dest, err)
	}
	return err
}
