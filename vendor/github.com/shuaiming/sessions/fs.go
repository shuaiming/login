package sessions

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// FileSession implement Session
type FileSession struct {
	MaxAge  int
	Expires time.Time
	Payload map[string]interface{}
}

func (f *FileSession) updateExpires() {
	f.Expires = time.Now().Add(time.Second * time.Duration(f.MaxAge))
}

func (f *FileSession) expired() bool {
	return time.Now().After(f.Expires)
}

// Load value from MemorySession
func (f *FileSession) Load(key string) (value interface{}, ok bool) {
	f.updateExpires()
	value, ok = f.Payload[key]
	return value, ok
}

// Store Session
func (f *FileSession) Store(key string, value interface{}) {
	f.updateExpires()
	f.Payload[key] = value
}

// Delete key from Session
func (f *FileSession) Delete(key string) {
	delete(f.Payload, key)
}

// FilesystemStore implement Store
type FilesystemStore struct {
	maxAge int
	dir    string
}

// NewFilesystemStore new FilesystemStore
func NewFilesystemStore(maxAge int, dir string) *FilesystemStore {
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Fatal(err)
	}

	// FIXME: can not register all possible types here
	gob.Register(map[string]string{})
	gob.Register(map[string]interface{}{})
	gob.Register(map[interface{}]interface{}{})

	return &FilesystemStore{maxAge: maxAge, dir: dir}
}

// Delete Session
func (ms *FilesystemStore) Delete(w http.ResponseWriter, sid string) {
	path := ms.sid2path(sid)
	if _, err := os.Stat(path); err == nil {
		os.Remove(path)
	}
}

// LoadOrCreate load or create Session
func (ms *FilesystemStore) LoadOrCreate(
	r *http.Request, sid string) (s Session, created bool) {
	path := ms.sid2path(sid)

	file, err := ioutil.ReadFile(path)

	if err == nil {
		var j FileSession
		r := bytes.NewBuffer(file)
		dec := gob.NewDecoder(r)
		if err := dec.Decode(&j); err == nil {
			return &j, false
		}
	}

	d := time.Second * time.Duration(ms.maxAge)
	s = &FileSession{
		MaxAge:  ms.maxAge,
		Expires: time.Now().Add(d),
		Payload: make(map[string]interface{}),
	}

	return s, true
}

// Store Session
func (ms *FilesystemStore) Store(
	w http.ResponseWriter, sid string, s Session) {
	// FIXME: dirty data may stored

	path := ms.sid2path(sid)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		log.Println(err)
		return
	}

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(s.(*FileSession)); err != nil {
		log.Println(err)
		return
	}

	if err := ioutil.WriteFile(path, b.Bytes(), 0640); err != nil {
		log.Println(err)
	}
}

// GC garbage collection
func (ms *FilesystemStore) GC() (int, int) {
	from, purged := 0, 0

	filepath.Walk(ms.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println(err)
			return err
		}

		if info.IsDir() {
			return nil
		}

		from++

		file, err := ioutil.ReadFile(path)
		if err != nil {
			log.Println(err)
			return err
		}

		var s FileSession
		r := bytes.NewBuffer(file)

		err = gob.NewDecoder(r).Decode(&s)
		if err != nil {
			// If a file can not be decoded,
			// It would be safer to keep it.
			log.Println(err)
			return err
		}

		if !s.expired() {
			return nil
		}

		err = os.Remove(path)
		if err != nil {
			log.Println(err)
			return err
		}

		purged++

		return err
	})

	return from, from - purged
}

func (ms *FilesystemStore) sid2path(sid string) string {
	sum := md5.Sum([]byte(sid))
	return fmt.Sprintf("%s/%x/%x/%x", ms.dir, sum[0], sum[1], sum)
}
