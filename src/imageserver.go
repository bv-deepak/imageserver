package main

import (
	"net/http"
	"encoding/json"
	"os"
	"io"
	"path/filepath"
	"archive/tar"
	"strings"
	"regexp"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"math/rand"
	"encoding/base64"
	"context"
	log "github.com/cihub/seelog"
)

type Configuration struct {
	Basepath string
	Storepath string
	Repopath string
	GDPRpath string
	ValidIPs []string
	StorePathRegex string
}
type bvTIDKey string

var bvThreadID = bvTIDKey("bv_tid")
var config = Configuration{}
var unauth_ip_error error = errors.New("Unauthorized IP address")
var invalid_path_error error = errors.New("Invalid path")
var app_path = filepath.Join(os.Getenv("PWD"))
var valid_storepath *regexp.Regexp

func abspath(path string) string {
	return filepath.Join(config.Basepath, path)
}

func bvCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := make([]byte, 4194304)
	for {
		r_size, r_err := src.Read(buf)
		if r_size > 0 {
			w_size, w_err := dst.Write(buf[0:r_size])
			if w_size > 0 {
				written += int64(w_size)
			}
			if w_err != nil {
				err = w_err
				break
			}
			if r_size != w_size {
				err = io.ErrShortWrite
				break
			}
		}
		if r_err != nil {
			if r_err != io.EOF {
				err = r_err
			}
			break
		}
	}
	return written, err
}

func base64EncodeHashKeys(hash map[string]interface{}) (map [string]interface{}){
	_hash := make(map[string]interface{})
	for key, val := range hash {
		_key := base64.StdEncoding.EncodeToString([]byte(key))
		_hash[_key] = val
	}
	return _hash
}

func renderJson(ctx context.Context, resp_writer http.ResponseWriter, hash map[string]interface{}, code int) {
	log.Infof("%d : RESPONSE : %d", ctx.Value(bvThreadID), code)
	resp_writer.Header().Set("Content-Type", "application/json")
	resp_writer.WriteHeader(code)
	escaped_hash := base64EncodeHashKeys(hash)
	json.NewEncoder(resp_writer).Encode(escaped_hash)
}

func isValidPath(path string) bool {
	_path := filepath.Clean(path)
	return valid_storepath.MatchString(_path)
}

func getRemoteIP(r *http.Request) string {
	return strings.Split(r.RemoteAddr, ":")[0]
}

func validateRemoteIP(ip string) bool {
	for _, val := range config.ValidIPs {
		if val == ip {
			return true
		}
	}
	return false
}

func fileExistsHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	filenames := req.Form["filenames"]
	storepath := req.FormValue("storepath")
	result := make(map[string]interface{})
	for _, fname := range filenames {
		filename := getFileName(storepath, fname)
		log.Debugf("%d : Filename : %s", ctx.Value(bvThreadID), filename)
		finfo, err := os.Stat(filename)
		if err == nil {
			result[fname] = finfo.Size()
		}
	}
	renderJson(ctx, resp_writer, result, http.StatusOK)
}

func removeFilesHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	result := make(map[string]interface{})
	failed_files := []string{}
	filenames := req.Form["filenames"]
	storepath := req.FormValue("storepath")
	for _, fname := range filenames {
		resp := make(map[string]interface{})
		filename := getFileName(storepath, fname)
		if !isValidPath(filename) {
			resp["status"] = false
			resp["error"] = "invalid file path"
			failed_files = append(failed_files, fname)
			continue
		}
		_, err := os.Stat(filename)
		if err == nil {
			err := os.Remove(filename)
			if err == nil {
				resp["status"] = true
			} else {
				resp["status"] = false
				resp["error"] = err.Error()
				failed_files = append(failed_files, fname)
			}
		} else {
			resp["status"] = false
			resp["error"] = err.Error()
			failed_files = append(failed_files, fname)
		}
		result[fname] = resp
	}
	result["failed_files"] = failed_files
	renderJson(ctx, resp_writer, result, http.StatusOK)
}

func readFileHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	fpath := req.FormValue("fpath")
	storepath := req.FormValue("storepath") 
	filename := getFileName(storepath, fpath)
	log.Debugf("%d : FILENAME : %s", ctx.Value(bvThreadID), filename)
	if !isValidPath(filename) {
		renderError(ctx, resp_writer, invalid_path_error, http.StatusForbidden, fpath)
		return
	}
	_, err := os.Stat(filename)
	if err != nil && os.IsNotExist(err) {
		renderError(ctx, resp_writer, err, http.StatusNotFound, fpath)
		return
	} else {
		file, err := os.Open(filename)
		if err != nil {
			renderError(ctx, resp_writer, err, http.StatusInternalServerError, fpath)
			return
		}
		defer file.Close()
		bvCopy(resp_writer, file)
	}
	log.Infof("%d : RESPONSE : %d", ctx.Value(bvThreadID), http.StatusOK)
}

func writeFileHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	status := make(map[string]interface{})
	fpath := req.FormValue("fpath")
	storepath := req.FormValue("storepath") 
	ofname := getFileName(storepath, fpath)
	log.Debugf("%d : FILENAME : %s", ctx.Value(bvThreadID), ofname)
	if !isValidPath(ofname) {
		renderError(ctx, resp_writer, invalid_path_error, http.StatusForbidden, fpath)
		return
	}
	os.MkdirAll(filepath.Dir(ofname), 0755)
	status[fpath] = writeStreamToFile(req.Body, ofname)
	defer req.Body.Close()
	renderJson(ctx, resp_writer, status, http.StatusOK)
}

func untarStream(ctx context.Context, reader io.Reader, storepath string) (map[string]interface{}, error) {
	filestats := make(map[string]interface{}) // {"filename" => {"md5" => "filemd5", "error" => "error if any"}}
	tarReader := tar.NewReader(reader)
	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Errorf("%d : %s", ctx.Value(bvThreadID), err.Error())
			return filestats, err
		}
		name := getFileName(storepath, header.Name)
		if !isValidPath(name) {
			return filestats, invalid_path_error
		}
		switch header.Typeflag {
		case tar.TypeDir:
			log.Debugf("%d : Directory : %s", ctx.Value(bvThreadID), name)
			os.MkdirAll(name, 0755)
		case tar.TypeReg:
			log.Debugf("%d : Regular file : %s", ctx.Value(bvThreadID), name)
			filestats[header.Name] = writeStreamToFile(tarReader, name)
		default:
			log.Errorf("%d : %s : %c : %s : %s", ctx.Value(bvThreadID), "Unable to parse", header.Typeflag, "in file", name)
			filestats[header.Name] = map[string]interface{}{"error" : "Unable to parse"}
		}
	}
	return filestats, nil
}

func writeStreamToFile(reader io.Reader, ofname string) map[string]interface{} {
	stats := make(map[string]interface{})
	const fixed_chunk = 4 * (1 << 20) // 4MB data at once
	os.MkdirAll(filepath.Dir(ofname), 0755)
	ofile, err := os.OpenFile(ofname, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Infof(err.Error())
		stats["error"] = err.Error()
		return stats
	}
	defer ofile.Close()
	buf := make([]byte, fixed_chunk)
	md5_hash := md5.New()
	for {
		read, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			stats["error"] = err.Error()
			break
		}
		if read == 0 {
			stats["md5"] = hex.EncodeToString(md5_hash.Sum(nil))
			break
		}
		if _, err := ofile.Write(buf[:read]); err != nil {
			stats["error"] = err.Error()
			break
		}
		md5_hash.Write(buf[:read])
	}
	finfo, err := os.Stat(ofname)
	if err == nil {
		stats["size"] = finfo.Size()
	}
	return stats
}

func putManyFilesHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	storepath := req.FormValue("storepath")
	log.Debugf("%d : STOREPATH : %s", ctx.Value(bvThreadID), storepath)
	result, err := untarStream(ctx, io.MultiReader(req.Body), storepath)
	defer req.Body.Close()
	if err != nil {
		result["Error"] = err
		renderError(ctx, resp_writer, err, http.StatusInternalServerError, storepath)
		return
	}
	renderJson(ctx, resp_writer, result, http.StatusOK)
}

func getManyFilesHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	filenames := req.Form["filenames"]
	storepath := req.FormValue("storepath")
	log.Debugf("%d : STOREPATH : %s", ctx.Value(bvThreadID), storepath)
	tarwriter := tar.NewWriter(resp_writer)
	defer tarwriter.Close()
	for _, fname := range filenames {
		filename := getFileName(storepath, fname)
		if !isValidPath(filename) {
			log.Errorf("%d : %s : %s", ctx.Value(bvThreadID), invalid_path_error.Error(), fname)
			continue
		}
		fi, err := os.Stat(filename)
		if err != nil {
			log.Errorf("%d : %s : %s", ctx.Value(bvThreadID), err.Error(), fname)
			continue
		}
		header, _:= tar.FileInfoHeader(fi, fi.Name())
		header.Name = filepath.Join(".", fname)
		if err := tarwriter.WriteHeader(header); err != nil {
			renderError(ctx, resp_writer, err, http.StatusInternalServerError, fname)
			log.Errorf("%d : %s : %s", ctx.Value(bvThreadID), err.Error(), fname)
			return
		}
		file, err := os.Open(filename)
		if err != nil {
			renderError(ctx, resp_writer, err, http.StatusInternalServerError, fname)
			log.Errorf("%d : %s : %s", ctx.Value(bvThreadID), err.Error(), fname)
			return
		}
		log.Debugf("%d : ADDED_FILE : %s", ctx.Value(bvThreadID), fname)
		bvCopy(tarwriter, file)
		file.Close()
	}
	log.Infof("%d : RESPONSE : %d", ctx.Value(bvThreadID), http.StatusOK)
}

func removeDir(dir string) (bool, error) {
	_, err := os.Stat(dir)
	if err != nil && os.IsNotExist(err) {
		return false, err
	}
	_dir, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer _dir.Close()
	names, err := _dir.Readdirnames(-1)
	if err != nil {
		return false, err
	}
	for _, name := range names {
		delete_path := filepath.Join(dir, name)
		if !isValidPath(delete_path) {
			return false, invalid_path_error
		}
		err = os.RemoveAll(delete_path)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func clearStoreHandler(ctx context.Context, resp_writer http.ResponseWriter, req *http.Request) {
	storepath := filepath.Join(config.Basepath, filepath.Clean(req.FormValue("storepath")))
	log.Infof("%d : STOREPATH : %s", ctx.Value(bvThreadID), storepath)
	status := make(map[string]interface{})
	ret, err := removeDir(storepath)
	if err != nil {
		renderError(ctx, resp_writer, err, http.StatusInternalServerError, storepath)
		log.Errorf("%d : %s : %s", ctx.Value(bvThreadID), err.Error(), storepath)
		return
	}
	status["status"] = ret
	renderJson(ctx, resp_writer, status, http.StatusOK)
}

func validator(fn func(context.Context, http.ResponseWriter, *http.Request), log_params bool) http.HandlerFunc {
	return func(resp_writer http.ResponseWriter, req *http.Request) {
		remote_ip := getRemoteIP(req)
		ctx := context.WithValue(req.Context(), bvThreadID, rand.Uint32())
		req.ParseMultipartForm(32 << 20) //read this 33554432 bytes at once rest is stored on disk
		if log_params {
			log.Infof("%d : REQUEST : %s : %s : %s : %s", ctx.Value(bvThreadID), remote_ip, req.Method, req.URL.Path, req.PostForm)
		} else {
			log.Infof("%d : REQUEST : %s : %s : %s", ctx.Value(bvThreadID), remote_ip, req.Method, req.URL.Path)
		}
		if !validateRemoteIP(remote_ip) {
			renderError(ctx, resp_writer, unauth_ip_error, http.StatusForbidden, remote_ip)
			return
		}
		fn(ctx, resp_writer, req)
	}
}

func renderError(ctx context.Context, resp_writer http.ResponseWriter, err error, code int, info string) {
	_err := make(map[string]interface{})
	_err["Error"] = err.Error() + " : " + info
	renderJson(ctx, resp_writer, _err, code)
}

func getFileName(rel_path string, filename string) string{
	log.Infof("Get---%s", rel_path)
	return filepath.Join(config.Basepath, filepath.Clean(rel_path), filepath.Clean(filename))
}

func loadConfig() (error) {
	file, err := os.Open(filepath.Join(app_path, "config/server_config.json"))
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	err := loadConfig()
	if err != nil {
		panic(err)
	}
	defer log.Flush()
	logger, err := log.LoggerFromConfigAsFile(filepath.Join(app_path, "config/log.xml"))
	if err != nil {
		panic(err)
	}
	log.ReplaceLogger(logger)
	valid_storepath = regexp.MustCompile(config.StorePathRegex)
  http.HandleFunc("/file_exists", validator(fileExistsHandler, false))
  http.HandleFunc("/remove_many_files", validator(removeFilesHandler, true))
  http.HandleFunc("/read_file", validator(readFileHandler, true))
  http.HandleFunc("/write_file", validator(writeFileHandler, true))
  http.HandleFunc("/put_many_files", validator(putManyFilesHandler, true))
  http.HandleFunc("/get_many_files", validator(getManyFilesHandler, true))
  http.HandleFunc("/clear_store", validator(clearStoreHandler, true))
	http.ListenAndServe(":32323", nil)
}
