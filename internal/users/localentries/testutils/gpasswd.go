package localgrouptestutils

//nolint:gci // We import unsafe as it is needed for go:linkname, but the nolint comment confuses gofmt and it adds
// a blank space between the imports, which creates problems with gci so we need to ignore it.
import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	//nolint:revive,nolintlint // needed for go:linkname, but only used in tests. nolintlint as false positive then.
	_ "unsafe"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd/internal/testutils"
)

// Mockgpasswd is the gpasswd mock.
func Mockgpasswd(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "" {
		return
	}

	args := os.Args
	for len(args) > 0 {
		if args[0] != "--" {
			args = args[1:]
			continue
		}
		args = args[1:]
		break
	}
	groupsFilePath, outputFilePath := args[0], args[1]

	// args are now the real args passed by authd.
	args = args[2:]

	d, err := os.ReadFile(groupsFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Mock: error reading group file: %v", err)
		os.Exit(1)
	}

	// Error if the group is not in the groupfile (we don’t handle substrings in the mock)
	group := args[len(args)-1]
	if !strings.Contains(string(d), group+":") {
		fmt.Fprintf(os.Stderr, "Error: %s in not in the group file", group)
		os.Exit(3)
	}

	// Other error
	if slices.Contains(args, "gpasswdfail") {
		fmt.Fprint(os.Stderr, "Error requested in mock")
		os.Exit(1)
	}

	f, err := os.OpenFile(outputFilePath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Mock: error opening file in append mode: %v", err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err := f.Write([]byte(strings.Join(args, " ") + "\n")); err != nil {
		fmt.Fprintf(os.Stderr, "Mock: error while writing in file: %v", err)
		f.Close()
		os.Exit(1)
	}
}

// SetupGPasswdMock setup the gpasswd mock and return the path to the file where the commands will be written.
//
// Tests that require this can not be run in parallel.
func SetupGPasswdMock(t *testing.T, groupsFilePath string) string {
	t.Helper()

	origin := defaultOptions
	t.Cleanup(func() { defaultOptions = origin })

	SetGroupPath(groupsFilePath)

	destCmdsFile := filepath.Join(t.TempDir(), "gpasswd.output")
	SetGpasswdCmd([]string{"env", "GO_WANT_HELPER_PROCESS=1",
		os.Args[0], "-test.run=TestMockgpasswd", "--",
		groupsFilePath, destCmdsFile,
	})

	return destCmdsFile
}

// AuthdIntegrationTestsEnvWithGpasswdMock returns the environment to pass to the authd daemon to use the gpasswd
// mock. In order to enable it, the authd binary must be built with the tag integrationtests.
// You need to install a TestMockgpasswd (generally calling Mockgpasswd) in your integration tests files.
func AuthdIntegrationTestsEnvWithGpasswdMock(t *testing.T, outputFilePath, groupsFilePath string) []string {
	t.Helper()

	gpasswdArgs := append([]string{
		"env", "GO_WANT_HELPER_PROCESS=1"},
		os.Args...)
	gpasswdArgs = append(gpasswdArgs,
		"-test.run=TestMockgpasswd", "--",
		groupsFilePath, outputFilePath,
	)

	return []string{
		"AUTHD_INTEGRATIONTESTS_GPASSWD_ARGS=" + strings.Join(gpasswdArgs, " "),
		"AUTHD_INTEGRATIONTESTS_GPASSWD_GRP_FILE_PATH=" + groupsFilePath,
	}
}

// RequireGPasswdOutput compare the output of gpasswd with the golden file.
func RequireGPasswdOutput(t *testing.T, destCmdsFile, goldenGpasswdPath string) {
	t.Helper()

	// TODO: this should be extracted in testutils, but still allow post-treatement of file like sorting.
	referenceFilePath := goldenGpasswdPath
	if testutils.UpdateEnabled() {
		// The file may already not exists.
		_ = os.Remove(goldenGpasswdPath)
		referenceFilePath = destCmdsFile
	}

	var shouldExists bool
	if _, err := os.Stat(referenceFilePath); err == nil {
		shouldExists = true
	}
	if !shouldExists {
		require.NoFileExists(t, destCmdsFile, "UpdateLocalGroups should not call gpasswd by did")
		return
	}

	gotGPasswd := idempotentGPasswdOutput(t, destCmdsFile)
	wantGPasswd := testutils.LoadWithUpdateFromGolden(t, gotGPasswd, testutils.WithGoldenPath(goldenGpasswdPath))
	require.Equal(t, wantGPasswd, gotGPasswd, "IsAuthenticated should return the expected combined data, but did not")
}

// idempotentGPasswdOutput sort and trim spaces around mock gpasswd output.
func idempotentGPasswdOutput(t *testing.T, cmdsFilePath string) string {
	t.Helper()

	d, err := os.ReadFile(cmdsFilePath)
	require.NoError(t, err, "Teardown: could not read dest trace file")

	// need to sort out all operations
	ops := strings.Split(string(d), "\n")
	slices.Sort(ops)
	content := strings.TrimSpace(strings.Join(ops, "\n"))

	return content
}
