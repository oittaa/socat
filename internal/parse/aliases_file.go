package parse

func init() {
	registerOptionAliases(map[string]string{
		"bind-tempname": "unix-bind-tempname",
		"o-nonblock":    "nonblock",
		"o-append":      "append",
		"direct":        "o-direct",
		"o_direct":      "o-direct",
		"ext2-noatime":  "fs-noatime",
		"ext3-noatime":  "fs-noatime",
		"o-trunc":       "trunc",
		"o-creat":       "creat",
		"o-excl":        "excl",
		"o-rdonly":      "rdonly",
		"o-wronly":      "wronly",
		"o-ndelay":      "nonblock",
		"delete":        "unlink",
		"remove":        "unlink",
		"uid-e":         "user-early",
		"gid-e":         "group-early",
		"so-type":       "socktype",
		"type":          "socktype",
		"f-setlk-wr":    "setlk",
		"f-setlkw-wr":   "setlkw",
		"f-setlk-rd":    "setlk-rd",
		"f-setlkw-rd":   "setlkw-rd",
	})
}
