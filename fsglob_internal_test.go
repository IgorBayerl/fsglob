package fsglob

import (
	"io"
	"io/fs"
	"path"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockFileInfo implements fs.FileInfo for testing
type MockFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
}

func (m MockFileInfo) Name() string       { return m.name }
func (m MockFileInfo) Size() int64        { return m.size }
func (m MockFileInfo) Mode() fs.FileMode  { return m.mode }
func (m MockFileInfo) ModTime() time.Time { return m.modTime }
func (m MockFileInfo) IsDir() bool        { return m.isDir }
func (m MockFileInfo) Sys() interface{}   { return nil }

// MockDirEntry implements fs.DirEntry for testing
type MockDirEntry struct {
	name  string
	isDir bool
	info  MockFileInfo
}

func (m MockDirEntry) Name() string               { return m.name }
func (m MockDirEntry) IsDir() bool                { return m.isDir }
func (m MockDirEntry) Type() fs.FileMode          { return m.info.Mode() }
func (m MockDirEntry) Info() (fs.FileInfo, error) { return m.info, nil }

// MockFilesystem implements filesystem.Filesystem for testing
type MockFilesystem struct {
	files     map[string]MockFileInfo
	dirs      map[string][]MockDirEntry
	cwd       string
	platform  string
	separator string
}

func NewMockFilesystem(platform string) *MockFilesystem {
	sep := "/"
	cwd := "/"
	if platform == "windows" {
		sep = `\`
		cwd = `C:\`
	}
	fs := &MockFilesystem{
		files:     make(map[string]MockFileInfo),
		dirs:      make(map[string][]MockDirEntry),
		cwd:       cwd,
		platform:  platform,
		separator: sep,
	}
	fs.AddFile(cwd, true)
	return fs
}

func (m *MockFilesystem) Platform() string {
	return m.platform
}

func (m *MockFilesystem) mockClean(p string) string {
	isUnc := false
	if m.platform == "windows" {
		p = strings.ReplaceAll(p, `\`, `/`)
		if strings.HasPrefix(p, "//") {
			isUnc = true
			p = p[1:]
		}
	}
	cleaned := path.Clean(p)
	if m.platform == "windows" {
		if isUnc {
			cleaned = "/" + cleaned
		}
		cleaned = strings.ReplaceAll(cleaned, `/`, `\`)
		if len(cleaned) == 2 && cleaned[1] == ':' {
			cleaned += `\`
		}
	}
	return cleaned
}

func (m *MockFilesystem) Stat(name string) (fs.FileInfo, error) {
	absName, err := m.Abs(name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	if info, exists := m.files[absName]; exists {
		return info, nil
	}
	if m.platform == "windows" {
		for p, info := range m.files {
			if strings.EqualFold(p, absName) {
				return info, nil
			}
		}
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (m *MockFilesystem) ReadDir(name string) ([]fs.DirEntry, error) {
	absName, err := m.Abs(name)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}

	handleFound := func(entries []MockDirEntry) ([]fs.DirEntry, error) {
		dirEntries := make([]fs.DirEntry, len(entries))
		for i, entry := range entries {
			dirEntries[i] = entry
		}
		return dirEntries, nil
	}

	if entries, exists := m.dirs[absName]; exists {
		return handleFound(entries)
	}

	if m.platform == "windows" {
		for p, entries := range m.dirs {
			if strings.EqualFold(p, absName) {
				return handleFound(entries)
			}
		}
	}

	return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
}

func (m *MockFilesystem) Getwd() (string, error) {
	return m.cwd, nil
}

func (m *MockFilesystem) isAbs(p string) bool {
	if m.platform == "windows" {
		return (len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, `/`)
	}
	return strings.HasPrefix(p, "/")
}

func (m *MockFilesystem) Abs(pathStr string) (string, error) {
	if m.platform == "windows" {
		pathStr = strings.ReplaceAll(pathStr, "/", `\`)
	} else {
		pathStr = strings.ReplaceAll(pathStr, `\`, "/")
	}

	if m.isAbs(pathStr) {
		return m.mockClean(pathStr), nil
	}

	fullPath := m.cwd + m.separator + pathStr
	return m.mockClean(fullPath), nil
}

func (m *MockFilesystem) mockDir(p string) string {
	if (m.platform == "windows" && len(p) == 3 && p[1] == ':' && p[2] == '\\') || (m.platform == "unix" && p == "/") {
		return p
	}

	var normalized string
	if m.platform == "windows" {
		normalized = strings.ReplaceAll(p, `\`, "/")
	} else {
		normalized = p
	}

	dir := path.Dir(normalized)

	if m.platform == "windows" {
		dir = strings.ReplaceAll(dir, "/", `\`)
		// path.Dir("C:/foo") returns "C:". We need to ensure it's "C:\"
		if len(dir) == 2 && dir[1] == ':' {
			return dir + `\`
		}
	}
	return dir
}

func (m *MockFilesystem) mockBase(p string) string {
	lastSep := strings.LastIndex(p, m.separator)
	if lastSep == -1 {
		return p
	}
	return p[lastSep+1:]
}

func (m *MockFilesystem) AddFile(path string, isDir bool) {
	absPath, _ := m.Abs(path)

	info := MockFileInfo{
		name:    m.mockBase(absPath),
		size:    100,
		mode:    0644,
		modTime: time.Now(),
		isDir:   isDir,
	}
	if isDir {
		info.mode = fs.ModeDir | 0755
		if _, exists := m.dirs[absPath]; !exists {
			m.dirs[absPath] = []MockDirEntry{}
		}
	}
	m.files[absPath] = info

	parent := m.mockDir(absPath)
	if parent != "" && parent != absPath {
		entry := MockDirEntry{
			name:  info.name,
			isDir: isDir,
			info:  info,
		}
		m.dirs[parent] = append(m.dirs[parent], entry)
	}
}

func (m *MockFilesystem) SetCwd(cwd string) {
	absCwd, _ := m.Abs(cwd)
	m.cwd = absCwd
}

// unused methods in this package
func (m *MockFilesystem) MkdirAll(path string, perm fs.FileMode) error               { return nil }
func (m *MockFilesystem) Create(path string) (io.WriteCloser, error)                 { return nil, nil }
func (m *MockFilesystem) Open(path string) (fs.File, error)                          { return nil, nil }
func (m *MockFilesystem) ReadFile(path string) ([]byte, error)                       { return nil, nil }
func (m *MockFilesystem) WriteFile(path string, data []byte, perm fs.FileMode) error { return nil }

// Test helper functions
func setupLinuxFS() *MockFilesystem {
	fs := NewMockFilesystem("unix")
	fs.SetCwd("/home/user")

	// Create directory structure
	fs.AddFile("/home", true)
	fs.AddFile("/home/user", true)
	fs.AddFile("/home/user/documents", true)
	fs.AddFile("/home/user/documents/file1.txt", false)
	fs.AddFile("/home/user/documents/file2.txt", false)
	fs.AddFile("/home/user/documents/report.pdf", false)
	fs.AddFile("/home/user/documents/subdir", true)
	fs.AddFile("/home/user/documents/subdir/nested.txt", false)
	fs.AddFile("/home/user/documents/subdir/deep", true)
	fs.AddFile("/home/user/documents/subdir/deep/file.log", false)
	fs.AddFile("/home/user/pictures", true)
	fs.AddFile("/home/user/pictures/photo1.jpg", false)
	fs.AddFile("/home/user/pictures/photo2.png", false)
	fs.AddFile("/tmp", true)
	fs.AddFile("/tmp/temp1.tmp", false)
	fs.AddFile("/tmp/temp2.tmp", false)

	return fs
}

func setupWindowsFS() *MockFilesystem {
	fs := NewMockFilesystem("windows")
	fs.SetCwd("C:\\Users\\User")

	// Create directory structure
	fs.AddFile("C:\\Users", true)
	fs.AddFile("C:\\Users\\User", true)
	fs.AddFile("C:\\Users\\User\\Documents", true)
	fs.AddFile("C:\\Users\\User\\Documents\\file1.txt", false)
	fs.AddFile("C:\\Users\\User\\Documents\\file2.txt", false)
	fs.AddFile("C:\\Users\\User\\Documents\\report.pdf", false)
	fs.AddFile("C:\\Users\\User\\Documents\\subdir", true)
	fs.AddFile("C:\\Users\\User\\Documents\\subdir\\nested.txt", false)
	fs.AddFile("C:\\Users\\User\\Documents\\subdir\\deep", true)
	fs.AddFile("C:\\Users\\User\\Documents\\subdir\\deep\\file.log", false)
	fs.AddFile("C:\\Users\\User\\Pictures", true)
	fs.AddFile("C:\\Users\\User\\Pictures\\photo1.jpg", false)
	fs.AddFile("C:\\Users\\User\\Pictures\\photo2.png", false)
	fs.AddFile("C:\\Temp", true)
	fs.AddFile("C:\\Temp\\temp1.tmp", false)
	fs.AddFile("C:\\Temp\\temp2.tmp", false)

	return fs
}

func TestRegexOrStringCache(t *testing.T) {
	fs := setupLinuxFS()
	glob := NewGlob("documents/*.txt", fs)

	// First call should populate cache
	ros1, err := glob.createRegexOrString("*.txt")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Second call should return cached result
	ros2, err := glob.createRegexOrString("*.txt")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should be the same object (cached)
	if ros1 != ros2 {
		t.Error("Expected cached RegexOrString to be returned")
	}
}

func TestUngroup(t *testing.T) {
	testCases := []struct {
		name     string
		pattern  string
		expected []string
		hasError bool
	}{
		{
			name:     "simple brace expansion",
			pattern:  "{a,b}c",
			expected: []string{"ac", "bc"},
		},
		{
			name:     "no braces",
			pattern:  "abc",
			expected: []string{"abc"},
		},
		{
			name:     "nested braces",
			pattern:  "{a,b{c,d}}",
			expected: []string{"a", "bc", "bd"},
		},
		{
			name:     "multiple groups",
			pattern:  "{a,b}{c,d}",
			expected: []string{"ac", "ad", "bc", "bd"},
		},
		{
			name:     "unbalanced braces",
			pattern:  "{a,b",
			hasError: true,
		},
		{
			name:     "empty group",
			pattern:  "{}",
			expected: []string{""},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := ungroup(tc.pattern)

			if tc.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			sort.Strings(results)
			sort.Strings(tc.expected)

			if !reflect.DeepEqual(results, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, results)
			}
		})
	}
}

func TestGlobToRegexPattern(t *testing.T) {
	testCases := []struct {
		name       string
		pattern    string
		ignoreCase bool
		expected   string
		hasError   bool
	}{
		{
			name:       "simple asterisk",
			pattern:    "*.txt",
			ignoreCase: false,
			expected:   "^[^/\\\\]*\\.txt$",
		},
		{
			name:       "question mark",
			pattern:    "file?.txt",
			ignoreCase: false,
			expected:   "^file.\\.txt$",
		},
		{
			name:       "case insensitive",
			pattern:    "*.TXT",
			ignoreCase: true,
			expected:   "(?i)^[^/\\\\]*\\.TXT$",
		},
		{
			name:       "character class",
			pattern:    "file[12].txt",
			ignoreCase: false,
			expected:   "^file[12]\\.txt$",
		},
		{
			name:       "double asterisk",
			pattern:    "**",
			ignoreCase: false,
			expected:   "^.*$",
		},
		{
			name:       "unterminated character class",
			pattern:    "file[12.txt",
			ignoreCase: false,
			hasError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := globToRegexPattern(tc.pattern, tc.ignoreCase)

			if tc.hasError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result != tc.expected {
				t.Errorf("Expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func BenchmarkRegexCache(b *testing.B) {
	fs := setupLinuxFS()
	glob := NewGlob("documents/*.txt", fs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := glob.createRegexOrString("*.txt")
		if err != nil {
			b.Fatalf("Unexpected error: %v", err)
		}
	}
}

// Test platform-specific path handling
func TestPlatformSpecificPaths(t *testing.T) {
	t.Run("unix_paths", func(t *testing.T) {
		fs := setupLinuxFS()
		glob := NewGlob("/home/user/documents/*.txt", fs)

		if !glob.isAbsolutePath("/home/user/documents/file.txt") {
			t.Error("Expected Unix absolute path to be recognized")
		}

		if glob.isAbsolutePath("relative/path.txt") {
			t.Error("Expected Unix relative path to not be recognized as absolute")
		}

		normalized := glob.normalizePathForPattern("home\\user\\documents")
		expected := "home/user/documents"
		if normalized != expected {
			t.Errorf("Expected %q, got %q", expected, normalized)
		}
	})

	t.Run("windows_paths", func(t *testing.T) {
		fs := setupWindowsFS()
		glob := NewGlob("C:\\Users\\User\\Documents\\*.txt", fs)

		if !glob.isAbsolutePath("C:\\Users\\User\\Documents\\file.txt") {
			t.Error("Expected Windows absolute path to be recognized")
		}

		if !glob.isAbsolutePath(`\\server\share\file.txt`) {
			t.Error("Expected Windows UNC path to be recognized")
		}

		if glob.isAbsolutePath(`relative\path.txt`) {
			t.Error("Expected Windows relative path to not be recognized as absolute")
		}

		normalized := glob.normalizePathForFS("Users/User/Documents")
		expected := `Users\User\Documents`
		if normalized != expected {
			t.Errorf("Expected %q, got %q", expected, normalized)
		}
	})
}

// Test concurrent access to cache
func TestConcurrentCacheAccess(t *testing.T) {
	fs := setupLinuxFS()

	// Run multiple goroutines accessing the cache simultaneously
	done := make(chan bool)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			glob := NewGlob("documents/*.txt", fs)
			_, err := glob.createRegexOrString("*.txt")
			if err != nil {
				errors <- err
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Check for errors
	select {
	case err := <-errors:
		t.Fatalf("Unexpected error in concurrent access: %v", err)
	default:
		// No errors, test passed
	}
}

// Test path normalization edge cases
func TestPathNormalizationEdgeCases(t *testing.T) {
	testCases := []struct {
		name     string
		platform string
		input    string
		expected string
	}{
		{
			name:     "windows_mixed_separators",
			platform: "windows",
			input:    "C:/Users\\User/Documents",
			expected: `C:\Users\User\Documents`,
		},
		{
			name:     "unix_backslashes",
			platform: "unix",
			input:    `home\user\documents`,
			expected: "home/user/documents",
		},
		{
			name:     "windows_unc_path",
			platform: "windows",
			input:    "//server/share/file.txt",
			expected: `\\server\share\file.txt`,
		},
		{
			name:     "empty_path",
			platform: "unix",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fs := NewMockFilesystem(tc.platform)
			glob := NewGlob("test", fs)

			result := glob.normalizePathForFS(tc.input)
			if tc.name == "windows_unc_path" {
				assert.Equal(t, `\\server\share\file.txt`, strings.ReplaceAll(tc.input, "/", `\`))
			} else {
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

// Test RegexOrString functionality
func TestRegexOrStringFunctionality(t *testing.T) {
	testCases := []struct {
		name        string
		pattern     string
		input       string
		ignoreCase  bool
		shouldMatch bool
		expectRegex bool
	}{
		{
			name:        "literal_match",
			pattern:     "file.txt",
			input:       "file.txt",
			ignoreCase:  false,
			shouldMatch: true,
			expectRegex: false,
		},
		{
			name:        "literal_case_insensitive",
			pattern:     "file.txt",
			input:       "FILE.TXT",
			ignoreCase:  true,
			shouldMatch: true,
			expectRegex: false,
		},
		{
			name:        "regex_match",
			pattern:     "file*.txt",
			input:       "file123.txt",
			ignoreCase:  false,
			shouldMatch: true,
			expectRegex: true,
		},
		{
			name:        "regex_no_match",
			pattern:     "file*.txt",
			input:       "document.pdf",
			ignoreCase:  false,
			shouldMatch: false,
			expectRegex: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fs := setupLinuxFS()
			glob := NewGlob("test", fs)
			glob.IgnoreCase = tc.ignoreCase

			ros, err := glob.createRegexOrString(tc.pattern)
			require.NoError(t, err)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if ros.IsRegex != tc.expectRegex {
				t.Errorf("Expected IsRegex=%v, got %v", tc.expectRegex, ros.IsRegex)
			}

			match := ros.IsMatch(tc.input)
			if match != tc.shouldMatch {
				t.Errorf("Expected match=%v, got %v", tc.shouldMatch, match)
			}
		})
	}
}
