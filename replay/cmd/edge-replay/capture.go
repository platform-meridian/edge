package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
)

type record struct {
	Seq    uint64 `json:"seq"`
	T      int64  `json:"t"`
	Conn   string `json:"conn"`
	Stream uint64 `json:"stream"`
	Method string `json:"method"`
	Dir    string `json:"dir"`
	B64    []byte `json:"b64,omitempty"`
	Code   uint32 `json:"code,omitempty"`
	Msg    string `json:"msg,omitempty"`
}

func open(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".gz") {
		return f, nil
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{z, f}, nil
}

func readCapture(path string) ([]record, error) {
	r, err := open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var out []record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<30)
	for sc.Scan() {
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			// A capture cut by a power loss ends in a torn line.
			break
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}
