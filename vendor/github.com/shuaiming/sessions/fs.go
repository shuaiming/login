package sessions

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"errors"
	"fmt"
	"io/fs"
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

// Empty 会话里没有任何数据
func (f *FileSession) Empty() bool {
	return len(f.Payload) == 0
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
	if err := os.Remove(ms.sid2path(sid)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Println(err)
	}
}

// LoadOrCreate load or create Session
func (ms *FilesystemStore) LoadOrCreate(
	r *http.Request, sid string) (s Session, created bool) {
	path := ms.sid2path(sid)

	file, err := os.ReadFile(path)

	if err == nil {
		var j FileSession
		dec := gob.NewDecoder(bytes.NewBuffer(file))
		if err := dec.Decode(&j); err == nil {
			// MaxAge/Expires 是写进文件里的旧值：调大 sess_ttl 只对新会话
			// 生效，已经在用的会一直按旧值顺延。这里按当前配置刷新一次，
			// 改完重启就对已有会话生效。
			j.MaxAge = ms.maxAge
			j.updateExpires()

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

	fsession, ok := s.(*FileSession)
	if !ok {
		log.Printf("sessions: unexpected session type %T", s)
		return
	}

	path := ms.sid2path(sid)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		log.Println(err)
		return
	}

	var b bytes.Buffer
	enc := gob.NewEncoder(&b)

	if err := enc.Encode(fsession); err != nil {
		log.Println(err)
		return
	}

	// 先写临时文件再改名。直接覆盖的话，读的人可能拿到写了一半的文件，
	// 解码失败会被当成新会话，用户莫名其妙掉线。
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		log.Println(err)
		return
	}

	tmpName := tmp.Name()

	// 0600：会话里有登录态，没必要给同组用户读
	if err := tmp.Chmod(0600); err != nil {
		log.Println(err)
	}

	if _, err := tmp.Write(b.Bytes()); err != nil {
		log.Println(err)
		tmp.Close()
		os.Remove(tmpName)
		return
	}

	if err := tmp.Close(); err != nil {
		log.Println(err)
		os.Remove(tmpName)
		return
	}

	if err := os.Rename(tmpName, path); err != nil {
		log.Println(err)
		os.Remove(tmpName)
	}
}

// GC garbage collection
func (ms *FilesystemStore) GC() (int, int) {
	from, purged := 0, 0

	err := filepath.Walk(ms.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Println(err)
			}

			// 单个文件出错不该让整轮 GC 提前结束
			return nil
		}

		if info.IsDir() {
			return nil
		}

		from++

		file, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Println(err)
			}

			return nil
		}

		var s FileSession

		err = gob.NewDecoder(bytes.NewBuffer(file)).Decode(&s)
		if err != nil {
			// 解不出来的（旧格式、或者写坏的文件）留着也没用，
			// 下次请求还会再撞一次。以前这里 return err，一个坏文件
			// 就让整轮 GC 停在那里，后面的都清不掉。
			if time.Since(info.ModTime()) > time.Second*time.Duration(ms.maxAge) {
				if err := os.Remove(path); err == nil {
					purged++
				}
			}

			return nil
		}

		if !s.expired() {
			return nil
		}

		if err := os.Remove(path); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				log.Println(err)
			}

			return nil
		}

		purged++

		return nil
	})
	if err != nil {
		log.Println(err)
	}

	return from, from - purged
}

func (ms *FilesystemStore) sid2path(sid string) string {
	sum := md5.Sum([]byte(sid))
	return fmt.Sprintf("%s/%x/%x/%x", ms.dir, sum[0], sum[1], sum)
}
