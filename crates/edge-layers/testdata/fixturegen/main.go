// Builds a containerd root with containerd's own code: its content store,
// metadata DB, overlayfs snapshotter and unpacker. Run inside `unshare -rm`
// (the applier mounts). Regenerate ../containerd-root.tar.gz with:
//
//	go build -o fixturegen . && mkdir root &&
//	unshare -rm ./fixturegen root root/bolt-large.db root/imagecache && cd root &&
//	tar --exclude=work --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - . |
//	gzip -9n > ../../containerd-root.tar.gz
//
// Three k8s.io images, each a distinct base layer under a ca-certificates layer
// sharing one path set but not content, plus one active snapshot. Two more are
// pulled into namespace system as Talos pulls kubelet and etcd; GC then deletes
// the second's layer blobs, which survive only in imagecache/.
//
// <large.db> is a plain bbolt file deep enough for branch and overflow pages.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff/apply"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/unpack"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay"
	"github.com/containerd/platforms"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

type file struct {
	path string
	data []byte
}

func layer(files ...file) (gz []byte, diffID digest.Digest) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	epoch := time.Unix(0, 0)
	dirs := map[string]bool{}
	for _, f := range files {
		var parents []string
		for d := filepath.Dir(f.path); d != "."; d = filepath.Dir(d) {
			parents = append([]string{d}, parents...)
		}
		for _, d := range parents {
			if !dirs[d] {
				dirs[d] = true
				must(tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./" + d + "/", Mode: 0o755, ModTime: epoch}))
			}
		}
		must(tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "./" + f.path, Mode: 0o644, Size: int64(len(f.data)), ModTime: epoch}))
		_, err := tw.Write(f.data)
		must(err)
	}
	must(tw.Close())
	diffID = digest.FromBytes(raw.Bytes())
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, err := zw.Write(raw.Bytes())
	must(err)
	must(zw.Close())
	return z.Bytes(), diffID
}

func bundle(version, certs int) []byte {
	var b strings.Builder
	for i := 0; i < certs; i++ {
		fmt.Fprintf(&b, "# v%d cert %d\n-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
			version, i, strings.Repeat(fmt.Sprintf("MIIC%02d%02d", version, i), 16))
	}
	return []byte(b.String())
}

func put(ctx context.Context, cs content.Store, mt string, b []byte) ocispec.Descriptor {
	d := ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
	must(content.WriteBlob(ctx, cs, d.Digest.String(), bytes.NewReader(b), d))
	return d
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func large(path string) {
	db, err := bolt.Open(path, 0o644, nil)
	must(err)
	must(db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("big"))
		if err != nil {
			return err
		}
		for i := 0; i < 1500; i++ {
			v := []byte("valueval")
			if i%500 == 0 {
				v = bytes.Repeat([]byte{'o'}, 9000)
			}
			if err := b.Put([]byte(fmt.Sprintf("key-%05d", i)), v); err != nil {
				return err
			}
		}
		return nil
	}))
	must(db.Close())
}

type image struct {
	name   string
	layers [][]byte
	config []byte
}

// pull stores an image and unpacks it, labelling the manifest for GC as
// containerd's pull does with labelMap.
func pull(ctx context.Context, cs content.Store, sn snapshots.Snapshotter, is images.Store, img image,
	labelMap func(ocispec.Descriptor) []string) string {
	var ls []ocispec.Descriptor
	for _, l := range img.layers {
		ls = append(ls, put(ctx, cs, ocispec.MediaTypeImageLayerGzip, l))
	}
	cfgDesc := put(ctx, cs, ocispec.MediaTypeImageConfig, img.config)
	mf, err := json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    cfgDesc,
		Layers:    ls,
	})
	must(err)
	mfDesc := put(ctx, cs, ocispec.MediaTypeImageManifest, mf)
	must(images.WalkNotEmpty(ctx, images.SetChildrenMappedLabels(cs, images.ChildrenHandler(cs), labelMap), mfDesc))

	u, err := unpack.NewUnpacker(ctx, cs, unpack.WithUnpackPlatform(unpack.Platform{
		Platform:       platforms.All,
		SnapshotterKey: "overlayfs",
		Snapshotter:    sn,
		Applier:        apply.NewFileSystemApplier(cs),
	}))
	must(err)
	must(images.WalkNotEmpty(ctx, u.Unpack(images.ChildrenHandler(cs)), mfDesc))
	_, err = u.Wait()
	must(err)

	_, err = is.Create(ctx, images.Image{Name: img.name, Target: mfDesc})
	must(err)
	return string(mf)
}

func build(name string, files ...[]file) (image, []digest.Digest) {
	img := image{name: name}
	var ids []digest.Digest
	for _, fs := range files {
		gz, id := layer(fs...)
		img.layers = append(img.layers, gz)
		ids = append(ids, id)
	}
	cfg, err := json.Marshal(ocispec.Image{
		Platform: ocispec.Platform{OS: "linux", Architecture: "amd64"},
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: ids},
	})
	must(err)
	img.config = cfg
	return img, ids
}

// cacheImage writes img into dir as Talos's image cache holds it.
func cacheImage(dir string, img image, manifest string) {
	blob := func(b []byte) {
		p := filepath.Join(dir, "blob", strings.Replace(digest.FromBytes(b).String(), "sha256:", "sha256-", 1))
		must(os.MkdirAll(filepath.Dir(p), 0o755))
		must(os.WriteFile(p, b, 0o644))
	}
	for _, l := range img.layers {
		blob(l)
	}
	blob(img.config)
	repo, tag, _ := strings.Cut(img.name, ":")
	for _, p := range []string{
		filepath.Join(dir, "manifests", repo, "reference", tag),
		filepath.Join(dir, "manifests", repo, "digest", strings.Replace(digest.FromString(manifest).String(), "sha256:", "sha256-", 1)),
	} {
		must(os.MkdirAll(filepath.Dir(p), 0o755))
		must(os.WriteFile(p, []byte(manifest), 0o644))
	}
}

func main() {
	large(os.Args[2])
	root := os.Args[1]
	cacheDir := os.Args[3]
	ctx := namespaces.WithNamespace(context.Background(), "k8s.io")

	lcs, err := local.NewStore(filepath.Join(root, "io.containerd.content.v1.content"))
	must(err)
	sn, err := overlay.NewSnapshotter(filepath.Join(root, "io.containerd.snapshotter.v1.overlayfs"))
	must(err)
	metaDir := filepath.Join(root, "io.containerd.metadata.v1.bolt")
	must(os.MkdirAll(metaDir, 0o711))
	bdb, err := bolt.Open(filepath.Join(metaDir, "meta.db"), 0o644, nil)
	must(err)
	db := metadata.NewDB(bdb, lcs, map[string]snapshots.Snapshotter{"overlayfs": sn})
	must(db.Init(ctx))
	cs := db.ContentStore()
	msn := db.Snapshotter("overlayfs")
	is := metadata.NewImageStore(db)

	var tops []string
	var k8s []image
	for v := 1; v <= 3; v++ {
		img, ids := build(fmt.Sprintf("example.test/img%d:v1", v),
			[]file{
				{"usr/lib/os-release", []byte(fmt.Sprintf("ID=base%d\n", v))},
				{fmt.Sprintf("bin/tool%d", v), bytes.Repeat([]byte{byte(v)}, 4096*v)},
			},
			[]file{{"etc/ssl/certs/ca-certificates.crt", bundle(v, 10+5*v)}},
		)
		cacheImage(cacheDir, img, pull(ctx, cs, msn, is, img, images.ChildGCLabels))
		k8s = append(k8s, img)
		tops = append(tops, identity.ChainID(ids).String())
		fmt.Printf("img%d base=%s ca=%s chain=%s\n", v, ids[0], ids[1], tops[v-1])
	}

	_, err = msn.Prepare(ctx, "container-rw-1", tops[0],
		snapshots.WithLabels(map[string]string{"containerd.io/gc.root": "fixture"}))
	must(err)

	// Talos's own pulls: internal/pkg/containers/image/pull.go.
	sys := namespaces.WithNamespace(context.Background(), "system")
	img1 := k8s[0]
	img1.name = "example.test/img1-system:v1"
	cacheImage(cacheDir, img1, pull(sys, cs, msn, is, img1, images.ChildGCLabelsFilterLayers))
	kubelet, ids := build("ghcr.io/siderolabs/kubelet:v1",
		[]file{{"usr/local/bin/kubelet", bytes.Repeat([]byte{'k'}, 20000)}},
		[]file{{"etc/ssl/certs/ca-certificates.crt", bundle(4, 30)}},
	)
	cacheImage(cacheDir, kubelet, pull(sys, cs, msn, is, kubelet, images.ChildGCLabelsFilterLayers))
	fmt.Printf("kubelet base=%s ca=%s chain=%s\n", ids[0], ids[1], identity.ChainID(ids))

	stats, err := db.GarbageCollect(sys)
	must(err)
	fmt.Printf("gc: %+v\n", stats)

	must(bdb.Close())
	must(sn.Close())
}
