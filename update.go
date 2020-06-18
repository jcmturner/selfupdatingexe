package selfupdatingexe

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/jcmturner/mavendownload/download"
	"github.com/jcmturner/mavendownload/metadata"
	"github.com/jcmturner/mavendownload/pom"
)

type Distribution struct {
	Repo       string
	GroupID    string
	ArtifactID string
	client     *http.Client
}

func New(repo, groupID, artifactID, repoCAPEM string, cl *http.Client) Distribution {
	if cl == nil {
		cl = http.DefaultClient
	}
	// Create the http client that trusts the repo certificate
	cp := x509.NewCertPool()
	ok := cp.AppendCertsFromPEM([]byte(repoCAPEM))
	if !ok {
		panic("could not append cert to cert pool trust store")
	}
	tlsConfig := &tls.Config{RootCAs: cp}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	cl.Transport = transport
	return Distribution{
		Repo:       repo,
		GroupID:    groupID,
		ArtifactID: artifactID,
	}
}

// DownloadUpdate checks if the current executable has a SHA1 hash that matches the latest version.
// If not, then then latest is downloaded to the same path as the running executable.
// Whether there was an update and the path of the newly downloaded latest version is returned.
func (r Distribution) DownloadUpdate() (update bool, fname string, err error) {
	var v string
	update, v, err = r.Check()
	if err != nil {
		return
	}
	if update {
		var exe string
		exe, err = exePath()
		if err != nil {
			return
		}
		dir := filepath.Dir(exe)
		_, fname, err = download.Save(r.Repo, r.GroupID, r.ArtifactID, "", dir, v, r.client)
		err = os.Chmod(fname, 0744)
		return
	}
	return
}

// Check compares the current executable's SHA1 hash against that of the latest version's.
// Whether there should be an update is returned and the latest's version label.
func (r Distribution) Check() (update bool, version string, err error) {
	var lSHA1 string
	version, lSHA1, err = latest(r.Repo, r.GroupID, r.ArtifactID, r.client)
	if err != nil {
		return
	}
	thisSHA1, err := SHA1()
	if err != nil {
		return
	}
	if thisSHA1 != lSHA1 {
		update = true
		return
	}
	return
}

// Versions returns a map of versions to their SHA1 hash
func (r Distribution) Versions() (vs map[string]string, err error) {
	vs = make(map[string]string)
	var md metadata.MetaData
	md, err = metadata.Get(r.Repo, r.GroupID, r.ArtifactID, r.client)
	if err != nil {
		return
	}
	for _, v := range md.Versioning.Versions {
		p, e := pom.Get(r.Repo, r.GroupID, r.ArtifactID, v, r.client)
		if e != nil {
			err = e
			return
		}
		fname := fmt.Sprintf("%s-%s.%s", r.ArtifactID, v, p.Packaging)
		url := fmt.Sprintf("%s/%s/%s/%s/%s", strings.TrimRight(r.Repo, "/"),
			r.GroupID, r.ArtifactID, v, fname)
		sha1, e := metadata.SHA1(url, r.client)
		if e != nil {
			err = e
			return
		}
		vs[v] = sha1
	}
	return
}

// RemoveOldVersions searches the directory of the current running executable and removes any files whose SHA1 hash
// matches one of the pervious versions. The current executable and the latest will not be removed.
func (r Distribution) RemoveOldVersions() error {
	vs, err := r.Versions()
	if err != nil {
		return err
	}
	_, lSHA1, err := latest(r.Repo, r.GroupID, r.ArtifactID, r.client)
	if err != nil {
		return err
	}
	thisSHA1, err := SHA1()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	files, err := ioutil.ReadDir(filepath.Dir(exe))
	if err != nil {
		return fmt.Errorf("error reading directory %s: %v", filepath.Dir(exe), err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		b, err := ioutil.ReadFile(f.Name())
		if err != nil {
			continue
		}
		hash := sha1.New()
		hash.Write(b)
		fSHA1 := hex.EncodeToString(hash.Sum(nil))
		if fSHA1 == thisSHA1 || fSHA1 == lSHA1 {
			// Do not remove if it is the this or latest version
			continue
		}
		for _, vSHA1 := range vs {
			if fSHA1 == vSHA1 {
				// remove if the file is one of the versions' hash
				os.Remove(f.Name())
			}
		}
	}
	return nil
}

// exePath returns the current excutable's absolute path.
func exePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	CPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		return "", err
	}
	return filepath.Abs(CPath)
}

// SHA1 calculates the SHA1 hash of the current running executable.
func SHA1() (string, error) {
	exe, err := exePath()
	if err != nil {
		return "", err
	}
	b, err := ioutil.ReadFile(exe)
	if err != nil {
		return "", err
	}
	hash := sha1.New()
	hash.Write(b)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// latest returns the version label and hash of the latest version.
func latest(repo, groupID, artifactID string, cl *http.Client) (string, string, error) {
	md, err := metadata.Get(repo, groupID, artifactID, cl)
	if err != nil {
		return "", "", err
	}
	p, err := pom.Get(repo, groupID, artifactID, md.Versioning.Latest, cl)
	if err != nil {
		return md.Versioning.Latest, "", err
	}
	fname := fmt.Sprintf("%s-%s.%s", artifactID, md.Versioning.Latest, p.Packaging)
	url := fmt.Sprintf("%s/%s/%s/%s/%s", strings.TrimRight(repo, "/"),
		groupID, artifactID, md.Versioning.Latest, fname)
	hash, err := metadata.SHA1(url, cl)
	if err != nil {
		return md.Versioning.Latest, "", err
	}
	return md.Versioning.Latest, hash, nil
}
