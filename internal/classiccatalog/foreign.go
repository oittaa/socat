package classiccatalog

// foreignPublic is documented classic spellings that are never a requirement
// on linux, darwin, or windows. They stay out of ImplementationBacklog.
// Platform-specific names that *are* required on one of those GOOS values
// belong in an expected-missing family file (for example binary on Windows).
//
// Classic baseline: tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
// official master af5388c898c7bb60997935aee93c223deba60c4a.
var foreignPublic = map[string]Gap{
	"abort-threshold":      {Reason: "documented; compiled only with HP-UX TCP_ABORT_THRESHOLD", Platforms: PlatNone},
	"conn-abort-threshold": {Reason: "documented; compiled only with HP-UX TCP_CONN_ABORT_THRESHOLD", Platforms: PlatNone},
	"b3600":                {Reason: "HP-UX B3600; not defined on glibc or Darwin termios", Platforms: PlatNone},
	"b900":                 {Reason: "HP-UX B900; not defined on glibc or Darwin termios", Platforms: PlatNone},
	"dsusp":                {Reason: "documented; compiled only with HP-UX VDSUSP", Platforms: PlatNone},
	"i-pop-all":            {Reason: "documented; compiled only with STREAMS I_POP", Platforms: PlatNone},
	"i-push":               {Reason: "documented; compiled only with STREAMS I_PUSH", Platforms: PlatNone},
	"keepinit":             {Reason: "documented; compiled only with OSF1 TCP_KEEPINIT", Platforms: PlatNone},
	"paws":                 {Reason: "documented; compiled only with OSF1 TCP_PAWS", Platforms: PlatNone},
	"sackena":              {Reason: "documented; compiled only with OSF1 TCP_SACKENA", Platforms: PlatNone},
	"tsoptena":             {Reason: "documented; compiled only with OSF1 TCP_TSOPTENA", Platforms: PlatNone},
	"md5sig":               {Reason: "documented TCP_MD5SUM (not Linux tcp-md5sig)", Platforms: PlatNone},
	"nshare":               {Reason: "documented; compiled only with O_NSHARE", Platforms: PlatNone},
	"rshare":               {Reason: "documented; compiled only with O_RSHARE", Platforms: PlatNone},
	"res-aaonly":           {Reason: "documented resolver option; compiled only with WITH_AA_ONLY", Platforms: PlatNone},
	"res-primary":          {Reason: "documented resolver option; compiled only with WITH_RES_PRIMARY", Platforms: PlatNone},
}
