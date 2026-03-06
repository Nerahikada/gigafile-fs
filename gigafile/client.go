// Package gigafile provides an HTTP client for gigafile.nu.
package gigafile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"regexp"
	"strconv"

	"github.com/google/uuid"
)

const (
	lifetime     = "100" // maximum retention days
	chunkSize    = 100 * 1024 * 1024 // 100 MB per chunk
	gigafileHome = "https://gigafile.nu/"
)

var serverRe = regexp.MustCompile(`var server = "(.+?)"`)

// UploadResult contains the result of a successful upload
type UploadResult struct {
	URL    string // e.g. https://66.gigafile.nu/0320-xxxx
	FileID string // e.g. 0320-xxxx
	Domain string // e.g. 66.gigafile.nu
}

// Client is a gigafile.nu HTTP client
type Client struct {
	http *http.Client
}

// New creates a new Client
func New() *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		http: &http.Client{Jar: jar},
	}
}

// fetchServer retrieves the upload server hostname from the gigafile.nu homepage
func (c *Client) fetchServer() (string, error) {
	resp, err := c.http.Get(gigafileHome)
	if err != nil {
		return "", fmt.Errorf("fetch server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read server page: %w", err)
	}
	m := serverRe.FindSubmatch(body)
	if m == nil {
		return "", fmt.Errorf("server variable not found in gigafile.nu homepage")
	}
	return string(m[1]), nil
}

// Upload uploads r (of known size) to gigafile.nu and returns the result.
// filename is the name stored on gigafile.nu (can be any string).
func (c *Client) Upload(filename string, size int64, r io.Reader) (*UploadResult, error) {
	server, err := c.fetchServer()
	if err != nil {
		return nil, err
	}

	token := uuid.New().String()
	totalChunks := int((size + chunkSize - 1) / chunkSize)
	if totalChunks == 0 {
		totalChunks = 1
	}

	buf := make([]byte, chunkSize)
	var result *UploadResult

	for chunkNo := range totalChunks {
		// Read one chunk
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return nil, fmt.Errorf("read chunk %d: %w", chunkNo, err)
		}
		if n == 0 {
			break
		}
		data := buf[:n]

		res, err := c.uploadChunk(server, token, filename, chunkNo, totalChunks, data)
		if err != nil {
			return nil, fmt.Errorf("upload chunk %d: %w", chunkNo, err)
		}
		if res != nil {
			result = res
		}
	}

	if result == nil {
		return nil, fmt.Errorf("upload completed but no URL received")
	}
	return result, nil
}

type chunkResponse struct {
	Status   int    `json:"status"`
	URL      string `json:"url"`
	Filename string `json:"filename"`
}

func (c *Client) uploadChunk(server, token, filename string, chunkNo, totalChunks int, data []byte) (*UploadResult, error) {
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	_ = w.WriteField("id", token)
	_ = w.WriteField("name", filename)
	_ = w.WriteField("chunk", strconv.Itoa(chunkNo))
	_ = w.WriteField("chunks", strconv.Itoa(totalChunks))
	_ = w.WriteField("lifetime", lifetime)

	// file part with explicit content-type
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="blob"`))
	h.Set("Content-Type", "application/octet-stream")
	fw, err := w.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(data); err != nil {
		return nil, err
	}
	w.Close()

	url := fmt.Sprintf("https://%s/upload_chunk.php", server)
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cr chunkResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if cr.Status != 0 {
		return nil, fmt.Errorf("upload_chunk.php returned status %d", cr.Status)
	}
	if cr.URL == "" {
		return nil, nil // intermediate chunk, no URL yet
	}

	// Parse domain from URL: https://NN.gigafile.nu/ID
	domainRe := regexp.MustCompile(`^https?://([^/]+)/`)
	dm := domainRe.FindStringSubmatch(cr.URL)
	domain := ""
	if dm != nil {
		domain = dm[1]
	}

	return &UploadResult{
		URL:    cr.URL,
		FileID: cr.Filename,
		Domain: domain,
	}, nil
}

// Download streams the file identified by domain+fileID into w.
// It handles the cookie handshake required by gigafile.nu.
// If rangeHeader is non-empty it is forwarded (e.g. "bytes=0-1023").
func (c *Client) Download(domain, fileID string, w io.Writer, rangeHeader string) error {
	// Step 1: visit download page to get cookie
	pageURL := fmt.Sprintf("https://%s/%s", domain, fileID)
	if _, err := c.http.Get(pageURL); err != nil {
		return fmt.Errorf("fetch download page: %w", err)
	}

	// Step 2: download the file
	dlURL := fmt.Sprintf("https://%s/download.php?file=%s", domain, fileID)
	req, err := http.NewRequest(http.MethodGet, dlURL, nil)
	if err != nil {
		return err
	}
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	_, err = io.Copy(w, resp.Body)
	return err
}

// DownloadResponse is like Download but returns the http.Response for streaming control.
// Caller is responsible for closing resp.Body.
func (c *Client) DownloadResponse(domain, fileID string, rangeHeader string) (*http.Response, error) {
	// Step 1: cookie handshake
	pageURL := fmt.Sprintf("https://%s/%s", domain, fileID)
	if _, err := c.http.Get(pageURL); err != nil {
		return nil, fmt.Errorf("fetch download page: %w", err)
	}

	// Step 2: open download stream
	dlURL := fmt.Sprintf("https://%s/download.php?file=%s", domain, fileID)
	req, err := http.NewRequest(http.MethodGet, dlURL, nil)
	if err != nil {
		return nil, err
	}
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}
	return resp, nil
}
