package permissions

// All those functions and methods are only for tests.
// They are not exported, and guarded by testing assertions.

import (
	"fmt"
	"math"
	"os/user"
	"strconv"
	"strings"

	"github.com/ubuntu/authd/internal/testsdetection"
)

// Z_ForTests_WithCurrentUserAsRoot returns an Option that sets the rootUID to the current user's UID.
//
// nolint:revive,nolintlint // We want to use underscores in the function name here.
func Z_ForTests_WithCurrentUserAsRoot() Option {
	testsdetection.MustBeTesting()

	uid := currentUserUID()
	return func(o *options) {
		o.rootUID = uid
	}
}

// currentUserUID returns the current user UID or panics.
func currentUserUID() uint32 {
	testsdetection.MustBeTesting()

	u, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("could not get current user: %v", err))
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 0)
	if err != nil || uid > math.MaxUint32 {
		panic(fmt.Sprintf("current uid is not an uint32 (%v): %v", u.Uid, err))
	}

	return uint32(uid)
}

// Z_ForTests_SetCurrentUserAsRoot mutates a default permission to the current user's UID if currentUserAsRoot is true.
//
// nolint:revive,nolintlint // We want to use underscores in the function name here.
func (m *Manager) Z_ForTests_SetCurrentUserAsRoot(currentUserAsRoot bool) {
	testsdetection.MustBeTesting()

	if !currentUserAsRoot {
		m.rootUID = defaultOptions.rootUID
		return
	}

	m.rootUID = currentUserUID()
}

// Z_ForTests_IdempotentPermissionError strips the UID from the permission error message.
//
// nolint:revive,nolintlint // We want to use underscores in the function name here.
func Z_ForTests_IdempotentPermissionError(msg string) string {
	testsdetection.MustBeTesting()

	return strings.ReplaceAll(msg, fmt.Sprint(currentUserUID()), "XXXX")
}

// Z_ForTests_DefaultCurrentUserAsRoot mocks the current user as root for the permission manager.
//
// nolint:revive,nolintlint // We want to use underscores in the function name here.
func Z_ForTests_DefaultCurrentUserAsRoot() {
	testsdetection.MustBeTesting()

	defaultOptions.rootUID = currentUserUID()
}
