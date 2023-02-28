package common

import (
	"regexp"
	"strings"

	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/pkg/utils"
)

func CanWrite(meta *model.Meta, path string) bool {
	if meta == nil || !meta.Write {
		return false
	}
	return meta.WSub || meta.Path == path
}

func CanAccess(user *model.User, meta *model.Meta, reqPath string, password string) bool {
	// if the reqPath is in hide (only can check the nearest meta) and user can't see hides, can't access
	if meta != nil && !user.CanSeeHides() && meta.Hide != "" && !utils.IsSubPath(meta.Path, reqPath) {
		for _, hide := range strings.Split(meta.Hide, "\n") {
			re := regexp.MustCompile(hide)
			if re.MatchString(reqPath[len(meta.Path)+1:]) {
				return false
			}
		}
	}

	// if user can access without password, allow access
	if user.CanAccessWithoutPassword() {
		return true
	}

	// check if the reqPath is a file
	if !utils.IsDir(reqPath) {
		return true
	}

	// if the user is a guest and the reqPath is a directory, require password
	if user.IsGuest() && meta != nil && meta.Password != "" && utils.IsSubPath(meta.Path, reqPath) {
		return meta.Password == password
	}

	// if meta is nil or password is empty, allow access
	if meta == nil || meta.Password == "" {
		return true
	}

	// if meta doesn't apply to sub_folder, allow access
	if !utils.IsSubPath(meta.Path, reqPath) && !meta.PSub {
		return true
	}

	// validate password
	return meta.Password == password
}
