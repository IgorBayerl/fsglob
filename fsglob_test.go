package fsglob_test

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/IgorBayerl/fsglob"
	"github.com/IgorBayerl/fsglob/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Cross-platform execution helper
func forPlatforms(t *testing.T, fn func(t *testing.T, fs *MockFilesystem)) {
	t.Helper()

	t.Run("unix", func(t *testing.T) {
		t.Parallel()
		fn(t, setupLinuxFS())
	})

	t.Run("windows", func(t *testing.T) {
		t.Parallel()
		fn(t, setupWindowsFS())
	})
}

// Mock filesystem
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
func (m MockFileInfo) Sys() any           { return nil }

type MockDirEntry struct {
	name  string
	isDir bool
	info  MockFileInfo
}

func (m MockDirEntry) Name() string               { return m.name }
func (m MockDirEntry) IsDir() bool                { return m.isDir }
func (m MockDirEntry) Type() fs.FileMode          { return m.info.Mode() }
func (m MockDirEntry) Info() (fs.FileInfo, error) { return m.info, nil }

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
	// Add the root directory
	fs.AddFile(cwd, true)
	return fs
}

func (m *MockFilesystem) Platform() string { return m.platform }

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
	abs, err := m.Abs(name)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}

	handleFound := func(entries []MockDirEntry) ([]fs.DirEntry, error) {
		out := make([]fs.DirEntry, len(entries))
		for i := range entries {
			out[i] = entries[i]
		}
		return out, nil
	}

	if entries, ok := m.dirs[abs]; ok {
		return handleFound(entries)
	}

	if m.platform == "windows" {
		for p, entries := range m.dirs {
			if strings.EqualFold(p, abs) {
				return handleFound(entries)
			}
		}
	}

	if _, err := m.Stat(name); err == nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fmt.Errorf("not a directory")}
	}

	return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
}

func (m *MockFilesystem) Getwd() (string, error) { return m.cwd, nil }

func (m *MockFilesystem) isAbs(p string) bool {
	if m.platform == "windows" {
		return (len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')) || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, `/`)
	}
	return strings.HasPrefix(p, "/")
}

func (m *MockFilesystem) Abs(path string) (string, error) {
	if m.platform == "windows" {
		path = strings.ReplaceAll(path, "/", `\`)
	} else {
		path = strings.ReplaceAll(path, `\`, "/")
	}

	if m.isAbs(path) {
		return m.mockClean(path), nil
	}

	fullPath := m.cwd + m.separator + path
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
	if m.platform == "windows" && lastSep == 2 && p[1] == ':' { // C:\ is base of C:\foo
		return p[lastSep+1:]
	}
	if lastSep == len(p)-1 {
		return ""
	}
	return p[lastSep+1:]
}

func (m *MockFilesystem) AddFile(path string, isDir bool) {
	abs, _ := m.Abs(path)
	info := MockFileInfo{
		name:    m.mockBase(abs),
		size:    100,
		mode:    0o644,
		modTime: time.Now(),
		isDir:   isDir,
	}
	if isDir {
		info.mode = fs.ModeDir | 0o755
		if _, exists := m.dirs[abs]; !exists {
			m.dirs[abs] = []MockDirEntry{}
		}
	}
	m.files[abs] = info

	parent := m.mockDir(abs)
	if parent != "" && parent != abs {
		entry := MockDirEntry{name: info.name, isDir: isDir, info: info}
		m.dirs[parent] = append(m.dirs[parent], entry)
	}
}

func (m *MockFilesystem) SetCwd(cwd string) {
	absCwd, _ := m.Abs(cwd)
	m.cwd = absCwd
}

// Stubbed-out methods not needed in these tests.
func (*MockFilesystem) MkdirAll(string, fs.FileMode) error          { return nil }
func (*MockFilesystem) Create(string) (io.WriteCloser, error)       { return nil, nil }
func (*MockFilesystem) Open(string) (fs.File, error)                { return nil, nil }
func (*MockFilesystem) ReadFile(string) ([]byte, error)             { return nil, nil }
func (*MockFilesystem) WriteFile(string, []byte, fs.FileMode) error { return nil }

// Test helper functions
func setupLinuxFS() *MockFilesystem {
	fs := NewMockFilesystem("unix")
	fs.SetCwd("/home/user")

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

func TestExpandNames_BasicPatterns_ReturnExpected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pattern  string
		wantUnix []string
		wantWin  []string
	}{
		{
			name:    "single asterisk",
			pattern: "documents/*.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
			},
		},
		{
			name:    "question mark",
			pattern: "documents/file?.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
			},
		},
		{
			name:    "double asterisk recursive",
			pattern: "documents/**/*.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
				"/home/user/documents/subdir/nested.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
				`C:\Users\User\Documents\subdir\nested.txt`,
			},
		},
		{
			name:    "character class",
			pattern: "documents/file[12].txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
			},
		},
		{
			name:    "brace expansion",
			pattern: "documents/{file1,file2}.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				g := fsglob.NewGlob(tc.pattern, fs)

				// Act
				got, err := g.ExpandNames()

				// Assert
				require.NoError(t, err)
				want := tc.wantUnix
				if fs.platform == "windows" {
					want = tc.wantWin
				}
				testutil.PathsMatch(t, want, got)
			})
		})
	}
}

func TestExpandNames_AbsolutePaths_CorrectPerPlatform(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pattern  string
		wantUnix []string
		wantWin  []string
	}{
		{
			name:    "absolute path unix",
			pattern: "/home/user/documents/*.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
			},
			wantWin: []string{}, // Should work differently on Windows
		},
		{
			name:     "absolute path windows",
			pattern:  `C:\Users\User\Documents\*.txt`,
			wantUnix: []string{}, // Should work differently on Unix
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				g := fsglob.NewGlob(tc.pattern, fs)

				// Act
				got, err := g.ExpandNames()

				// Assert
				require.NoError(t, err)
				want := tc.wantUnix
				if fs.platform == "windows" {
					want = tc.wantWin
				}
				testutil.PathsMatch(t, want, got)
			})
		})
	}
}

func TestExpandNames_RecursivePatterns_ReturnExpected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pattern  string
		wantUnix []string
		wantWin  []string
	}{
		{
			name:    "recursive all files",
			pattern: "documents/**",
			wantUnix: []string{
				"/home/user/documents",
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
				"/home/user/documents/report.pdf",
				"/home/user/documents/subdir",
				"/home/user/documents/subdir/nested.txt",
				"/home/user/documents/subdir/deep",
				"/home/user/documents/subdir/deep/file.log",
			},
			wantWin: []string{
				`C:\Users\User\Documents`,
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
				`C:\Users\User\Documents\report.pdf`,
				`C:\Users\User\Documents\subdir`,
				`C:\Users\User\Documents\subdir\nested.txt`,
				`C:\Users\User\Documents\subdir\deep`,
				`C:\Users\User\Documents\subdir\deep\file.log`,
			},
		},
		{
			name:    "recursive specific extension",
			pattern: "**/*.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
				"/home/user/documents/subdir/nested.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
				`C:\Users\User\Documents\subdir\nested.txt`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				g := fsglob.NewGlob(tc.pattern, fs)

				// Act
				got, err := g.ExpandNames()

				// Assert
				require.NoError(t, err)
				want := tc.wantUnix
				if fs.platform == "windows" {
					want = tc.wantWin
				}
				testutil.PathsMatch(t, want, got)
			})
		})
	}
}

func TestExpandNames_InvalidGlob_ReturnsError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
	}{
		{
			name:    "unbalanced braces",
			pattern: "documents/{file1,file2.txt",
		},
		{
			name:    "unterminated character class",
			pattern: "documents/file[12.txt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				g := fsglob.NewGlob(tc.pattern, fs)

				// Act
				got, err := g.ExpandNames()

				// Assert
				assert.Error(t, err, "Expected an error for malformed pattern %q", tc.pattern)
				assert.Empty(t, got, "Expected empty results for malformed pattern")
			})
		})
	}
}

func TestExpandNames_NonGlobInputs_ReturnsPathOrEmpty(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pattern  string
		wantUnix []string
		wantWin  []string
	}{
		{
			name:     "empty pattern",
			pattern:  "",
			wantUnix: []string{},
			wantWin:  []string{},
		},
		{
			name:    "literal path exists",
			pattern: "documents/file1.txt",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
			},
		},
		{
			name:     "literal path doesn't exist",
			pattern:  "documents/nonexistent.txt",
			wantUnix: []string{},
			wantWin:  []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				g := fsglob.NewGlob(tc.pattern, fs)

				// Act
				got, err := g.ExpandNames()

				// Assert
				require.NoError(t, err)
				want := tc.wantUnix
				if fs.platform == "windows" {
					want = tc.wantWin
				}
				testutil.PathsMatch(t, want, got)
			})
		})
	}
}

func TestExpandNames_NoMatch_ReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
		// Arrange
		g := fsglob.NewGlob("documents/*.nonexistent", fs)

		// Act
		got, err := g.ExpandNames()

		// Assert
		assert.NoError(t, err)
		assert.Empty(t, got, "Expected empty results for non-matching pattern")
	})
}

func TestExpandNames_LargeTree_FindsAllTxtFiles(t *testing.T) {
	t.Parallel()

	// Arrange
	fs := NewMockFilesystem("unix")
	fs.SetCwd("/home/user")
	fs.AddFile("/home", true)
	fs.AddFile("/home/user", true)
	fs.AddFile("/home/user/large", true)

	expectedCount := 0
	for i := 0; i < 100; i++ {
		fs.AddFile(fmt.Sprintf("/home/user/large/file%d.txt", i), false)
		expectedCount++
		if i%10 == 0 {
			fs.AddFile(fmt.Sprintf("/home/user/large/subdir%d", i), true)
			for j := 0; j < 10; j++ {
				fs.AddFile(fmt.Sprintf("/home/user/large/subdir%d/nested%d.txt", i, j), false)
				expectedCount++
			}
		}
	}

	g := fsglob.NewGlob("large/**/*.txt", fs)

	// Act
	got, err := g.ExpandNames()

	// Assert
	require.NoError(t, err)
	assert.Len(t, got, expectedCount, "Expected to find all .txt files in the large tree")
}

func TestExpandNames_CaseSensitivity_VariousFlags(t *testing.T) {
	t.Parallel()

	addExtraFiles := func(fs *MockFilesystem) {
		if fs.platform == "unix" {
			fs.AddFile("/home/user/documents/File1.TXT", false)
			fs.AddFile("/home/user/documents/FILE2.txt", false)
		} else {
			fs.AddFile(`C:\Users\User\Documents\File1.TXT`, false)
			fs.AddFile(`C:\Users\User\Documents\FILE2.txt`, false)
		}
	}

	cases := []struct {
		name       string
		pattern    string
		ignoreCase bool
		wantUnix   []string
		wantWin    []string
	}{
		{
			"mixed-case sensitive", "documents/*.TXT", false,
			[]string{"/home/user/documents/File1.TXT"},
			[]string{`C:\Users\User\Documents\File1.TXT`},
		},
		{
			"mixed-case insensitive", "documents/*.TXT", true,
			[]string{"/home/user/documents/file1.txt", "/home/user/documents/file2.txt", "/home/user/documents/File1.TXT", "/home/user/documents/FILE2.txt"},
			[]string{`C:\Users\User\Documents\file1.txt`, `C:\Users\User\Documents\file2.txt`, `C:\Users\User\Documents\File1.TXT`, `C:\Users\User\Documents\FILE2.txt`},
		},
		{
			"lower-case sensitive", "documents/*.txt", false,
			[]string{"/home/user/documents/file1.txt", "/home/user/documents/file2.txt", "/home/user/documents/FILE2.txt"},
			[]string{`C:\Users\User\Documents\file1.txt`, `C:\Users\User\Documents\file2.txt`, `C:\Users\User\Documents\FILE2.txt`},
		},
		{
			"lower-case insensitive", "documents/*.txt", true,
			[]string{"/home/user/documents/file1.txt", "/home/user/documents/file2.txt", "/home/user/documents/File1.TXT", "/home/user/documents/FILE2.txt"},
			[]string{`C:\Users\User\Documents\file1.txt`, `C:\Users\User\Documents\file2.txt`, `C:\Users\User\Documents\File1.TXT`, `C:\Users\User\Documents\FILE2.txt`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				addExtraFiles(fs)
				g := fsglob.NewGlob(tc.pattern, fs, fsglob.WithIgnoreCase(tc.ignoreCase))

				// Act
				got, err := g.ExpandNames()

				// Assert
				require.NoError(t, err)
				want := tc.wantUnix
				if fs.platform == "windows" {
					want = tc.wantWin
				}
				testutil.PathsMatch(t, want, got)
			})
		})
	}
}

func TestExpandNames_ComplexBraceExpansion_ReturnsExpected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		pattern  string
		wantUnix []string
		wantWin  []string
	}{
		{
			name:    "nested braces",
			pattern: "documents/{file{1,2},report}.{txt,pdf}",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
				"/home/user/documents/report.pdf",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
				`C:\Users\User\Documents\report.pdf`,
			},
		},
		{
			name:    "cross-separator braces",
			pattern: "{documents,pictures}/*.{txt,jpg}",
			wantUnix: []string{
				"/home/user/documents/file1.txt",
				"/home/user/documents/file2.txt",
				"/home/user/pictures/photo1.jpg",
			},
			wantWin: []string{
				`C:\Users\User\Documents\file1.txt`,
				`C:\Users\User\Documents\file2.txt`,
				`C:\Users\User\Pictures\photo1.jpg`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
				// Arrange
				g := fsglob.NewGlob(tc.pattern, fs)

				// Act
				got, err := g.ExpandNames()

				// Assert
				require.NoError(t, err)
				want := tc.wantUnix
				if fs.platform == "windows" {
					want = tc.wantWin
				}
				testutil.PathsMatch(t, want, got)
			})
		})
	}
}

func TestExpandNames_DotAndDotDot_Patterns(t *testing.T) {
	t.Parallel()

	t.Run("current_directory", func(t *testing.T) {
		t.Parallel()
		forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
			// Arrange
			g := fsglob.NewGlob(".", fs)

			// Act
			got, err := g.ExpandNames()

			// Assert
			require.NoError(t, err)
			expectedCwd, _ := fs.Getwd()
			testutil.PathsMatch(t, []string{expectedCwd}, got)
		})
	})

	t.Run("parent_directory", func(t *testing.T) {
		t.Parallel()
		forPlatforms(t, func(t *testing.T, fs *MockFilesystem) {
			// Arrange
			g := fsglob.NewGlob("..", fs)

			// Act
			got, err := g.ExpandNames()

			// Assert
			require.NoError(t, err)
			cwd, _ := fs.Getwd()
			expectedParent := fs.mockDir(cwd)
			testutil.PathsMatch(t, []string{expectedParent}, got)
		})
	})
}

func TestGetFilesPublicAPI(t *testing.T) {
	t.Parallel()

	// Arrange
	dir := t.TempDir()
	cwd, err := os.Getwd()
	require.NoError(t, err) // Use require for test setup
	defer func() {
		err := os.Chdir(cwd)
		require.NoError(t, err, "failed to change back to original directory")
	}()

	err = os.Chdir(dir)
	require.NoError(t, err)

	// Act
	results, err := fsglob.GetFiles("*.nonexistent")

	// Assert
	require.NoError(t, err)
	assert.Empty(t, results, "expected empty results for non-matching pattern")

	// Act
	results, err = fsglob.GetFiles("")

	// Assert
	require.NoError(t, err)
	assert.Empty(t, results, "expected empty results for empty pattern")
}
