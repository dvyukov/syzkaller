// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/html"
	"github.com/google/syzkaller/pkg/vcs"
	"golang.org/x/net/context"
	db "google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
)

// This file contains web UI http handlers.

func initHTTPHandlers() {
	http.Handle("/", handlerWrapper(handleMain))
	http.Handle("/bug", handlerWrapper(handleBug))
	http.Handle("/text", handlerWrapper(handleText))
	http.Handle("/bisect_info", handlerWrapper(handleBisectInfo))
	http.Handle("/x/.config", handlerWrapper(handleTextX(textKernelConfig)))
	http.Handle("/x/log.txt", handlerWrapper(handleTextX(textCrashLog)))
	http.Handle("/x/report.txt", handlerWrapper(handleTextX(textCrashReport)))
	http.Handle("/x/repro.syz", handlerWrapper(handleTextX(textReproSyz)))
	http.Handle("/x/repro.c", handlerWrapper(handleTextX(textReproC)))
	http.Handle("/x/patch.diff", handlerWrapper(handleTextX(textPatch)))
	http.Handle("/x/bisect.txt", handlerWrapper(handleTextX(textLog)))
	http.Handle("/x/error.txt", handlerWrapper(handleTextX(textError)))
}

type uiMain struct {
	Header        *uiHeader
	Now           time.Time
	Log           []byte
	Managers      []*uiManager
	Jobs          []*uiJob
	BugNamespaces []*uiBugNamespace
}

type uiManager struct {
	Now                   time.Time
	Namespace             string
	Name                  string
	Link                  string
	CoverLink             string
	CurrentBuild          *uiBuild
	FailedBuildBugLink    string
	FailedSyzBuildBugLink string
	LastActive            time.Time
	LastActiveBad         bool
	CurrentUpTime         time.Duration
	MaxCorpus             int64
	MaxCover              int64
	TotalFuzzingTime      time.Duration
	TotalCrashes          int64
	TotalExecs            int64
}

type uiBuild struct {
	Time                time.Time
	SyzkallerCommit     string
	SyzkallerCommitLink string
	SyzkallerCommitDate time.Time
	KernelAlias         string
	KernelCommit        string
	KernelCommitLink    string
	KernelCommitTitle   string
	KernelCommitDate    time.Time
	KernelConfigLink    string
}

type uiCommit struct {
	Hash   string
	Title  string
	Link   string
	Author string
	CC     []string
	Date   time.Time
}

type uiBugPage struct {
	Header         *uiHeader
	Now            time.Time
	Bug            *uiBug
	BisectCause    *uiJob
	DupOf          *uiBugGroup
	Dups           *uiBugGroup
	Similar        *uiBugGroup
	SampleReport   []byte
	HasMaintainers bool
	Crashes        []*uiCrash
}

type uiBugNamespace struct {
	Name       string
	Caption    string
	FixedLink  string
	FixedCount int
	Managers   []*uiManager
	Groups     []*uiBugGroup
}

type uiBugGroup struct {
	Now           time.Time
	Caption       string
	Fragment      string
	Namespace     string
	ShowNamespace bool
	ShowPatch     bool
	ShowPatched   bool
	ShowStatus    bool
	ShowIndex     int
	Bugs          []*uiBug
}

type uiBug struct {
	Namespace      string
	Title          string
	NumCrashes     int64
	NumCrashesBad  bool
	BisectCause    bool
	FirstTime      time.Time
	LastTime       time.Time
	ReportedTime   time.Time
	ClosedTime     time.Time
	ReproLevel     dashapi.ReproLevel
	ReportingIndex int
	Status         string
	Link           string
	ExternalLink   string
	CreditEmail    string
	Commits        []*uiCommit
	PatchedOn      []string
	MissingOn      []string
	NumManagers    int
}

type uiCrash struct {
	Manager      string
	Time         time.Time
	Maintainers  string
	LogLink      string
	ReportLink   string
	ReproSyzLink string
	ReproCLink   string
	*uiBuild
}

type uiJob struct {
	Type            JobType
	Created         time.Time
	BugLink         string
	ExternalLink    string
	User            string
	Reporting       string
	Namespace       string
	Manager         string
	BugTitle        string
	BugID           string
	KernelAlias     string
	KernelCommit    string
	PatchLink       string
	Attempts        int
	Started         time.Time
	Finished        time.Time
	Duration        time.Duration
	CrashTitle      string
	CrashLogLink    string
	CrashReportLink string
	LogLink         string
	ErrorLink       string
	Commit          *uiCommit   // for conclusive bisection
	Commits         []*uiCommit // for inconclusive bisection
	Crash           *uiCrash
	Reported        bool
}

var bisectInfo = map[string]struct {
	correct          bool
	hardToReproduce  bool
	multipleCrashes  bool
	unrealtedCrashes bool
	skipInterfere    bool
	disabledConfig   bool
}{
	"0264f823322ea8600fbe3fb7e9e016569ca542d8": {false, false, true, true, false, false},
	"02bde0600a225e8efa31bdce2e7f1b822542fef1": {true, false, false, false, false, false},
	"106319f5d94ac049166744eee79e455ce4d0435c": {true, false, false, false, false, false},
	"4db14afc80049c484903a7cf4d36d9cb1618469f": {true, false, false, false, false, false},
	"cf86490d75109a7648fc749a4c9a8d59fabe398d": {true, false, false, false, false, false},
	"04933ddeeb1b542edf54b88ceccdac34de747a40": {true, false, true, false, false, false},
	"0519bd00ced4ae7f7c6f20bbfa5c0dfa4df51739": {true, false, true, false, false, false},
	"08e669746c0679bba6b119c2ffacff3bc6a5ce49": {false, true, false, true, false, false},
	"0c963236471bc9561fd3b38da03cd09482e90c72": {false, false, true, true, false, false},
	"10cd2ff2ccd320618b127ec50ea6e5a55461cd76": {false, false, false, true, false, false},
	"13de4605e86ebcf39093017dc255aa0fd6c2f12d": {false, false, false, true, false, false},
	"163388d1fb80146cd3ba22a11a5a1995c3eaaafe": {false, false, false, true, false, false},
	"16c9389ff3e0a921ddc98957e9a94c0913ad4669": {true, false, true, false, false, false},
	"17535f4bf5b322437f7c639b59161ce343fc55a9": {true, false, true, false, false, false},
	"17b1ffc681bc9f575cafe1ff72117b01d8c212fb": {false, true, true, false, false, false},
	"1b42faa2848963564a5b1b7f8c837ea7b55ffa50": {true, false, true, false, false, false},
	"1f5af6cb9a265f1d394769ba75542f756b489f1b": {true, false, true, false, false, false},
	"2109fb7c8fb7f76e8269485c0ca0f04e2e1ac3fc": {false, false, true, false, true, false},
	"229e0b718232b004dfddaeac61d8d66990ed247a": {true, true, true, false, false, false},
	"2318b559efec9fda6c77bd5c3d57c8fc3255d922": {true, true, true, false, false, false},
	"2410d22f1d8e5984217329dd0884b01d99e3e48d": {true, false, false, false, false, false},
	"24b68e26f36aefc69e86e97dc731558c6965115a": {true, false, true, true, false, false},
	"28b6bf730a5e8d288db5c794d5c6ccc49f746d74": {true, false, false, false, false, false},
	"2d6a9427fceb9941d6d87128130babe7e40baba0": {false, true, true, true, false, false},
	"2ec99b05d1b07c30c8e5d307e40651b106b20368": {true, false, false, false, false, false},
	"31b84e77557158a1031ca8c9476230bb186fb88c": {false, true, false, true, false, false},
	"32ab41bbdc0c28643c507dd0cf1eea1a9ce67837": {true, false, false, false, false, false},
	"342beb2b368a43cbb6533c00d758759b10fbc8d8": {false, true, true, true, false, false},
	"362d37ea5c9445929e633e81565b20e77d317b4f": {true, false, false, false, false, false},
	"36b975e34252647b1b3d5d8a164e4aae45bf6d60": {true, false, false, false, false, false},
	"38d36d1b26b4299bf964d50af4d79688d39ab960": {true, false, true, false, false, false},
	"3acd1155d48a5acc5d76711568b04926945a6885": {false, false, true, false, false, true},
	"47befb59c610a69f024db20b927dea80c88fc045": {false, false, true, false, false, true},
	"d708485af9edc3af35f3b4d554e827c6c8bf6b0f": {false, false, true, false, false, true},
	"4d03c161c6cc140b6234f534c6009d8c9da39f6c": {false, false, true, false, false, true},
	"3b87dcf5e5ba9a2043ee6ed716cb1de4e3ffa1f1": {true, false, true, false, false, false},
	"5a087c49cb6997c9e4544203afc1adbb289879a5": {true, false, true, false, false, false},
	"72c29c8d4d19164497518992e91cac2123fc083e": {true, false, true, false, false, false},
	"80a29a2cc44c85f71c3019d334592035b7299029": {true, false, true, false, false, false},
	"93e67d1ae66524b264d8308b7e275edc84d70ff7": {true, false, true, false, false, false},
	"9f65f4ff5604c1b1595452c46c31dcfb08515d57": {true, false, true, false, false, false},
	"3c9259df279d84b845e9708f0e51e35e4d02e1b0": {true, false, false, false, false, false},
	"3fd2badc3dc77e680e01b9330b217a361014a4f2": {true, false, false, false, false, false},
	"40cdeb3bf27f6ec1fa468f8d7fff780368704d67": {true, false, true, false, false, false},
	"41872265f1e3e0489eb0cc8762f8d48b3667afdb": {true, false, false, false, false, false},
	"44ae4b4fa7e6c6e92aa921d2ec20ce9fbee97939": {true, false, true, false, false, false},
	"4ad312cd74149ae58624039b5b3003faf6974e08": {true, false, true, false, false, false},
	"4b9e5e6290e3fdee367ea37949f3bda8d4ec87bd": {false, true, true, true, false, false},
	"4c0ccb254972cc51bdf6838cb1eff4fcc00de597": {true, false, true, false, false, false},
	"4cf5ee79b52a4797c5bd40a58bd6ab243d40de48": {true, false, true, false, false, false},
	"506214c97a1af183589a4caf4a8fa162a9f56cbd": {true, false, true, true, false, false},
	"573d37f073c715dbcb403479b2458105679b58b2": {true, false, true, false, false, false},
	"7cd3db70971bc10523485d12d95fdefa301fb819": {true, false, true, false, false, false},
	"7f79b2bbcf1a6057a25d5557562141d90624d5da": {false, true, true, false, false, false},
	"5df4f85d764ee89863d0294b4e0c87ef2fd2c624": {true, false, true, false, false, false},
	"6080a070da766e6f046055bb90af40df73a5d3ae": {false, true, false, true, false, false},
	"623c2e176b9d80b1872e7559e5b823b1ec4911b6": {false, true, true, false, false, false},
	"62aaa13b8b6bba7f5bca8c0defef34b9a1623135": {false, false, true, true, false, false},
	"6408a8ba0fa0e3940c5c2dfa40e808cbf4228689": {true, false, true, false, false, false},
	"163414c0fc6f717973e0a832acfba3dfc184707b": {false, false, false, true, false, false},
	"0ba17d70d062b2595e1f061231474800f076c7cb": {true, false, false, false, false, false},
	"55d929463ecf8859c0c4836a4f8f004cfec28cf7": {true, false, true, false, false, false},
	"6a6553c3d34bb00172b5cbd32f4912151b6133dc": {false, true, true, true, false, false},
	"6c137905024f86513297b035845acecb55fa9dab": {false, true, true, true, false, false},
	"6d5c55bc531f0ef83e8faca014cc123b4498f7a6": {false, false, false, true, false, false},
	"6d600a0ff2cc263bc4edbddf0f597e456e303978": {true, false, false, false, false, false},
	"7022420cc54310220ebad2da89e499bdb1f0f5e8": {true, false, false, false, false, false},
	"7250aa28cb43ada4cba944fe46d80f67435022ef": {true, false, false, true, false, false},
	"72dff36edffc3e8a3a0895aaf03b46d545a5dd5d": {true, false, true, false, false, false},
	"788ed2c7e973b69fd551ba6b5e21848dba2c1670": {true, false, true, false, false, false},
	"79994e7a1da2d2a0697da38e29910780fa320071": {false, false, true, true, true, false},
	"7f47ce544bdaed1a1c5d0b0adac201d136d5fc79": {false, true, true, true, true, false},
	"82425f52b09843fe8da85de87f9d590920bbe1fe": {false, true, true, false, false, false},
	"8340d4b8c7304ff0b43490a1b69ab3833dd7ad20": {true, false, false, false, false, false},
	"854553af64ddcb546a94e37dec96bca877d1d569": {true, false, false, false, false, false},
	"873d6bcb9c5df3932a42b4a4347fda2061bf0a64": {true, false, true, false, false, false},
	"8c04c0b0e814e1a2c5ae60f8b6ece3701bf561da": {false, false, true, true, false, false},
	"91cbd2d4963aa0a7fe7b94d1a5c2ec1e36fa67a1": {false, true, false, true, false, false},
	"fb195f91dc044978c1b186f1288b1eff61edcc20": {false, false, false, false, true, false},
	"f9cfa5c5564ffc453258d835293bf6e9881c5b1c": {true, false, false, false, false, false},
	"f620d34965777e9d309c58394ade94dbd3e3b0a8": {false, false, true, true, true, false},
	"f46c94afb217ab49c75350adbd467d86ae2b59a6": {true, false, true, false, false, false},
	"924b5574f42ebeddc94fad06f2fa329b199d58d3": {false, false, false, true, false, false},
	"979d00397272e11bc334ec842074d314bde41b90": {false, false, false, true, false, false},
	"99873243a442fffe0c5c6d9983e2d17b4680a60c": {true, false, false, false, false, false},
	"9abc0fdcdea0effb7b27984dbc1f336155cdad3f": {false, true, true, false, false, false},
	"9c65accb85b71ee72e58b2874fc7608a28e4d641": {true, false, true, false, false, false},
	"9f86fabfdd07b7257ccd37a8c105a58b162fa356": {true, false, true, false, false, false},
	"a1c27d97870876dcccbac41a965e46f672fc3855": {true, false, true, false, false, false},
	"a421ee23a2b5b657ab5b958226ee885a9113ac7a": {false, true, true, false, false, false},
	"a9796acbdecc1b2ba927578917755899c63c48af": {false, false, false, true, false, false},
	"aa17edc076b9f096667fb68bd5fec33a80038154": {true, false, false, false, false, false},
	"aaf17ca3f8ef677356e61bbe7e2c1af7f4398ec3": {true, false, false, false, false, false},
	"acdcbdeef8c25f03c392005e553773b19ab540e8": {true, false, false, false, false, false},
	"afc5098c1a0cb7cda8aa7fdb402153ff24fcf31c": {false, false, false, true, false, false},
	"b0192a79bb2d222d3e723d7db60dfb5e0ec0e570": {true, false, true, false, false, false},
	"b5d36424a183538dad060d0bef3ebc375e7a94eb": {false, true, true, true, false, false},
	"b61c24317d9e0a189c4fe3373273f43e29999b5a": {false, true, false, false, false, false},
	"b658eb696c8279d9951a4ceea79efba8a1d12467": {false, false, false, true, false, false},
	"b962be759f1c186a76fe71ba99eda6e23708dcd9": {false, false, false, true, false, false},
	"bc195cf62ac17381792072c72a692bf133c528d4": {true, false, true, false, false, false},
	"be0232f1d0792f426874fc0cf149fb1721a62d42": {false, true, true, true, false, false},
	"c14d620a28ea77843c2632f5b05b315c44a2dd06": {true, false, false, false, false, false},
	"c670fb9da2ce08f7b5101baa9426083b39ee9f90": {true, false, true, false, false, false},
	"c7e819884ddc3e9e16b0ed14d94c8c090ef53992": {true, false, true, false, false, false},
	"c97097e0408c6c6f60ac89b78faaf0e42663cbac": {false, true, false, false, false, false},
	"ca98e815aabdd1494eacb048d649ffd4fc916e2e": {true, false, false, false, false, false},
	"cb3b80ba8aa00f25e4fe8ddf1a381a6686803e28": {false, false, false, false, true, false},
	"cc7bc687e2a27a595a9e5a86e0f820f3d06b74a3": {true, false, false, false, false, false},
	"db947ce523c1649ed8917fd831b996bec8687c9f": {true, false, false, false, false, false},
	"dbd70f0407487a061d2d46fdc6bccc94b95ce3c0": {true, false, true, false, false, false},
	"dd5aa153a2344f5f39e656692bc58dfe86e0423f": {false, false, false, true, false, false},
	"e1d2492507fca6102dbce03c16b40a21130c8dbf": {false, false, true, true, false, false},
	"ea46a31df5253b18deb1e18c429c1483b111cbce": {false, true, false, true, false, false},
	"ee7cf202a47281cda2e5a76bd1ba0683a10c2a65": {false, true, false, true, false, false},
	"eff432af8dea9e5e0d14acdae66b51ef49ccb5ee": {false, true, true, false, false, false},
	/*
		"XXXXXXXXX": {xxxxxxxxx, false, false, false, false, false},
	*/
}

func handleBisectInfo(c context.Context, w http.ResponseWriter, r *http.Request) error {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Filter("Type=", JobBisectCause).
		GetAll(c, &jobs)
	if err != nil {
		return err
	}
	rows := [][]string{
		[]string{
			"ID",
			"Bug link",
			"Bisect log",
			"Start",
			"Skip",
			"Commits",
			"Correct",
			"Racy/flaky",
			"Different manifestations",
			"Unrelated crashes",
			"Skip interference",
			"Disabled config",
			"Cause commit",
			"Crash title",
			"Final crash",
			"Other crashes",
		},
	}
	const numBuckets = 6
	buckets := [numBuckets]string{
		"v5.0..v4.18",
		"v4.17..v4.14",
		"v4.13..v4.10",
		"v4.9..v4.6",
		"v4.5..v4.1",
		"total",
	}
	bucketMap := map[string]int{
		"v5.0":  0,
		"v4.20": 0,
		"v4.19": 0,
		"v4.18": 0,
		"v4.17": 1,
		"v4.16": 1,
		"v4.15": 1,
		"v4.14": 1,
		"v4.13": 2,
		"v4.12": 2,
		"v4.11": 2,
		"v4.10": 2,
		"v4.9":  3,
		"v4.8":  3,
		"v4.7":  3,
		"v4.6":  3,
		"v4.5":  4,
		"v4.4":  4,
		"v4.3":  4,
		"v4.2":  4,
		"v4.1":  4,
	}
	var (
		bisectCrashRe   = regexp.MustCompile("(?:run #[0-9]|all runs): crashed: (.*?)\n")
		skipOther       = []byte("git bisect skip")
		bucketTotal     [numBuckets]int
		bucketCorrect   [numBuckets]int
		bucketFlaky     [numBuckets]int
		bucketMulti     [numBuckets]int
		bucketUnrelated [numBuckets]int
		bucketSkip      [numBuckets]int
		bucketConfig    [numBuckets]int
	)
	for i, job := range jobs {
		if job.Finished.IsZero() || job.Error != 0 {
			continue
		}
		bisectLog, _, err := getText(c, textLog, job.Log)
		if err != nil {
			return err
		}
		startCommit := "-"
		const bisectStart = "# git bisect start "
		if pos := bytes.Index(bisectLog, []byte(bisectStart)); pos != -1 {
			pos += len(bisectStart)
			end := bytes.IndexByte(bisectLog[pos:], '\n')
			if end != -1 {
				end += pos
			} else {
				end = len(bisectLog)
			}
			startCommit = strings.Split(string(bisectLog[pos:end]), " ")[1]
		}
		title := job.BugTitle
		if ln := len(title); ln > 5 && title[ln-1] == ')' && title[ln-3] == '(' && title[ln-4] == ' ' {
			title = title[:ln-4]
		}
		dedup := map[string]bool{
			title:          true,
			job.CrashTitle: true,
		}
		var allCrashes []string
		for _, res := range bisectCrashRe.FindAllSubmatch(bisectLog, -1) {
			crash := string(res[1])
			if dedup[crash] {
				continue
			}
			dedup[crash] = true
			allCrashes = append(allCrashes, crash)
		}
		if len(allCrashes) == 0 {
			allCrashes = append(allCrashes, "-")
		}
		skip := "-"
		if bytes.Contains(bisectLog, skipOther) {
			skip = "Y"
		}
		commit := "-"
		if len(job.Commits) == 1 {
			commit = job.Commits[0].Title
		}
		Y := func(f bool) string {
			if f {
				return "Y"
			}
			return "-"
		}
		ID := keys[i].Parent().StringID()
		info, haveInfo := bisectInfo[ID]
		correct := Y(info.correct)
		if !haveInfo {
			correct = "TODO"
		}
		rows = append(rows, []string{
			ID, // ID
			fmt.Sprintf("%v/bug?id=%v", appURL(c), ID), // Bug link
			externalLink(c, textLog, job.Log),          // Bisect log
			startCommit,                                // Start commit
			skip,                                       // Skip
			fmt.Sprintf("%v", len(job.Commits)),        // Commits
			correct,
			Y(info.hardToReproduce),
			Y(info.multipleCrashes),
			Y(info.unrealtedCrashes),
			Y(info.skipInterfere),
			Y(info.disabledConfig),
			commit,                         // Commit
			title,                          // Crash title
			job.CrashTitle,                 // Final crash
			strings.Join(allCrashes, ", "), // Other crashes
		})
		if !haveInfo {
			continue
		}
		if info.correct && startCommit == "-" {
			continue
		}
		if startCommit == "-" {
			startCommit = "v4.1"
		}
		bucketIdx, ok := bucketMap[startCommit]
		if !ok {
			return fmt.Errorf("no bucket for commit %q", startCommit)
		}
		const total = numBuckets - 1
		bucketTotal[total]++
		bucketTotal[bucketIdx]++
		if info.multipleCrashes {
			bucketMulti[total]++
			bucketMulti[bucketIdx]++
		}
		if info.correct {
			bucketCorrect[total]++
			bucketCorrect[bucketIdx]++
		}
		if info.hardToReproduce && !info.correct {
			bucketFlaky[total]++
			bucketFlaky[bucketIdx]++
		}
		if info.unrealtedCrashes && !info.correct {
			bucketUnrelated[total]++
			bucketUnrelated[bucketIdx]++
		}
		if info.skipInterfere && !info.correct {
			bucketSkip[total]++
			bucketSkip[bucketIdx]++
		}
		if info.disabledConfig && !info.correct {
			bucketConfig[total]++
			bucketConfig[bucketIdx]++
		}
	}
	buf := new(bytes.Buffer)
	for _, row := range rows {
		for _, s := range row {
			fmt.Fprintf(buf, "\"%v\"\t", s)
		}
		fmt.Fprintf(buf, "\n")
	}
	fmt.Fprintf(buf, "\n\n\n")
	fmt.Fprintf(buf, "-")
	for _, name := range buckets {
		fmt.Fprintf(buf, "\t%v", name)
	}
	fmt.Fprintf(buf, "\n")
	fmt.Fprintf(buf, "correct, %%")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%.2f",
			float64(bucketCorrect[i])/float64(bucketTotal[i])*100)
	}
	fmt.Fprintf(buf, "\n")

	fmt.Fprintf(buf, "correct")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%v", bucketCorrect[i])
	}
	fmt.Fprintf(buf, "\n")

	fmt.Fprintf(buf, "multiple manifestations, %%")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%.2f", float64(bucketMulti[i])/float64(bucketTotal[i])*100)
	}
	fmt.Fprintf(buf, "\n")

	fmt.Fprintf(buf, "failed due to racy/flaky, %%")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%.2f", float64(bucketFlaky[i])/float64(bucketTotal[i]-bucketCorrect[i])*100)
	}
	fmt.Fprintf(buf, "\n")

	fmt.Fprintf(buf, "failed due to unrelated crashes, %%")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%.2f", float64(bucketUnrelated[i])/float64(bucketTotal[i]-bucketCorrect[i])*100)
	}
	fmt.Fprintf(buf, "\n")

	fmt.Fprintf(buf, "failed due to skipped commits, %%")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%.2f", float64(bucketSkip[i])/float64(bucketTotal[i]-bucketCorrect[i])*100)
	}
	fmt.Fprintf(buf, "\n")

	fmt.Fprintf(buf, "failed due to disabled configs, %%")
	for i := range buckets {
		fmt.Fprintf(buf, "\t%.2f", float64(bucketConfig[i])/float64(bucketTotal[i]-bucketCorrect[i])*100)
	}
	fmt.Fprintf(buf, "\n")

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(buf.Bytes())
	return nil
}

// handleMain serves main page.
func handleMain(c context.Context, w http.ResponseWriter, r *http.Request) error {
	var errorLog []byte
	var managers []*uiManager
	var jobs []*uiJob
	accessLevel := accessLevel(c, r)

	if r.FormValue("fixed") == "" {
		var err error
		managers, err = loadManagers(c, accessLevel)
		if err != nil {
			return err
		}
		if accessLevel == AccessAdmin {
			errorLog, err = fetchErrorLogs(c)
			if err != nil {
				return err
			}
			jobs, err = loadRecentJobs(c)
			if err != nil {
				return err
			}
		}
	}
	bugNamespaces, err := fetchBugs(c, r)
	if err != nil {
		return err
	}
	for _, ns := range bugNamespaces {
		for _, mgr := range managers {
			if ns.Name == mgr.Namespace {
				ns.Managers = append(ns.Managers, mgr)
			}
		}
	}
	data := &uiMain{
		Header:        commonHeader(c, r),
		Now:           timeNow(c),
		Log:           errorLog,
		Jobs:          jobs,
		BugNamespaces: bugNamespaces,
	}
	if accessLevel == AccessAdmin {
		data.Managers = managers
	}
	return serveTemplate(w, "main.html", data)
}

// handleBug serves page about a single bug (which is passed in id argument).
func handleBug(c context.Context, w http.ResponseWriter, r *http.Request) error {
	bug := new(Bug)
	if id := r.FormValue("id"); id != "" {
		bugKey := db.NewKey(c, "Bug", id, 0, nil)
		if err := db.Get(c, bugKey, bug); err != nil {
			return err
		}
	} else if extID := r.FormValue("extid"); extID != "" {
		var err error
		bug, _, err = findBugByReportingID(c, extID)
		if err != nil {
			return err
		}
	} else {
		return ErrDontLog(fmt.Errorf("mandatory parameter id/extid is missing"))
	}
	accessLevel := accessLevel(c, r)
	if err := checkAccessLevel(c, r, bug.sanitizeAccess(accessLevel)); err != nil {
		return err
	}
	state, err := loadReportingState(c)
	if err != nil {
		return err
	}
	managers, err := managerList(c, bug.Namespace)
	if err != nil {
		return err
	}
	var dupOf *uiBugGroup
	if bug.DupOf != "" {
		dup := new(Bug)
		if err := db.Get(c, db.NewKey(c, "Bug", bug.DupOf, 0, nil), dup); err != nil {
			return err
		}
		if accessLevel >= dup.sanitizeAccess(accessLevel) {
			dupOf = &uiBugGroup{
				Now:     timeNow(c),
				Caption: "Duplicate of",
				Bugs:    []*uiBug{createUIBug(c, dup, state, managers)},
			}
		}
	}
	uiBug := createUIBug(c, bug, state, managers)
	crashes, sampleReport, err := loadCrashesForBug(c, bug)
	if err != nil {
		return err
	}
	dups, err := loadDupsForBug(c, r, bug, state, managers)
	if err != nil {
		return err
	}
	similar, err := loadSimilarBugs(c, r, bug, state)
	if err != nil {
		return err
	}
	var bisectCause *uiJob
	if bug.BisectCause > BisectPending {
		job, _, jobKey, _, err := loadBisectJob(c, bug)
		if err != nil {
			return err
		}
		crash := new(Crash)
		crashKey := db.NewKey(c, "Crash", "", job.CrashID, bug.key(c))
		if err := db.Get(c, crashKey, crash); err != nil {
			return fmt.Errorf("failed to get crash: %v", err)
		}
		build, err := loadBuild(c, bug.Namespace, crash.BuildID)
		if err != nil {
			return err
		}
		bisectCause = makeUIJob(job, jobKey, crash, build)
	}
	hasMaintainers := false
	for _, crash := range crashes {
		if len(crash.Maintainers) != 0 {
			hasMaintainers = true
			break
		}
	}
	data := &uiBugPage{
		Header:         commonHeader(c, r),
		Now:            timeNow(c),
		Bug:            uiBug,
		BisectCause:    bisectCause,
		DupOf:          dupOf,
		Dups:           dups,
		Similar:        similar,
		SampleReport:   sampleReport,
		HasMaintainers: hasMaintainers,
		Crashes:        crashes,
	}
	return serveTemplate(w, "bug.html", data)
}

// handleText serves plain text blobs (crash logs, reports, reproducers, etc).
func handleTextImpl(c context.Context, w http.ResponseWriter, r *http.Request, tag string) error {
	var id int64
	if x := r.FormValue("x"); x != "" {
		xid, err := strconv.ParseUint(x, 16, 64)
		if err != nil || xid == 0 {
			return ErrDontLog(fmt.Errorf("failed to parse text id: %v", err))
		}
		id = int64(xid)
	} else {
		// Old link support, don't remove.
		xid, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
		if err != nil || xid == 0 {
			return ErrDontLog(fmt.Errorf("failed to parse text id: %v", err))
		}
		id = xid
	}
	crash, err := checkTextAccess(c, r, tag, id)
	if err != nil {
		return err
	}
	data, ns, err := getText(c, tag, id)
	if err != nil {
		return err
	}
	if err := checkAccessLevel(c, r, config.Namespaces[ns].AccessLevel); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Unfortunately filename does not work in chrome on linux due to:
	// https://bugs.chromium.org/p/chromium/issues/detail?id=608342
	w.Header().Set("Content-Disposition", "inline; filename="+textFilename(tag))
	if tag == textReproSyz {
		// Add link to documentation and repro opts for syzkaller reproducers.
		w.Write([]byte(syzReproPrefix))
		if crash != nil {
			fmt.Fprintf(w, "#%s\n", crash.ReproOpts)
		}
	}
	w.Write(data)
	return nil
}

func handleText(c context.Context, w http.ResponseWriter, r *http.Request) error {
	return handleTextImpl(c, w, r, r.FormValue("tag"))
}

func handleTextX(tag string) contextHandler {
	return func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		return handleTextImpl(c, w, r, tag)
	}
}

func textFilename(tag string) string {
	switch tag {
	case textKernelConfig:
		return ".config"
	case textCrashLog:
		return "log.txt"
	case textCrashReport:
		return "report.txt"
	case textReproSyz:
		return "repro.syz"
	case textReproC:
		return "repro.c"
	case textPatch:
		return "patch.diff"
	case textLog:
		return "bisect.txt"
	case textError:
		return "error.txt"
	default:
		return "text.txt"
	}
}

func fetchBugs(c context.Context, r *http.Request) ([]*uiBugNamespace, error) {
	state, err := loadReportingState(c)
	if err != nil {
		return nil, err
	}
	accessLevel := accessLevel(c, r)
	onlyFixed := r.FormValue("fixed")
	var res []*uiBugNamespace
	for ns, cfg := range config.Namespaces {
		if accessLevel < cfg.AccessLevel {
			continue
		}
		if onlyFixed != "" && onlyFixed != ns {
			continue
		}
		uiNamespace, err := fetchNamespaceBugs(c, accessLevel, ns, state, onlyFixed != "")
		if err != nil {
			return nil, err
		}
		res = append(res, uiNamespace)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Caption < res[j].Caption
	})
	return res, nil
}

func fetchNamespaceBugs(c context.Context, accessLevel AccessLevel, ns string,
	state *ReportingState, onlyFixed bool) (*uiBugNamespace, error) {
	query := db.NewQuery("Bug").Filter("Namespace=", ns)
	if onlyFixed {
		query = query.Filter("Status=", BugStatusFixed)
	}
	var bugs []*Bug
	_, err := query.GetAll(c, &bugs)
	if err != nil {
		return nil, err
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return nil, err
	}
	fixedCount := 0
	groups := make(map[int][]*uiBug)
	bugMap := make(map[string]*uiBug)
	var dups []*Bug
	for _, bug := range bugs {
		if bug.Status == BugStatusFixed {
			fixedCount++
		}
		if bug.Status == BugStatusInvalid || bug.Status == BugStatusFixed != onlyFixed {
			continue
		}
		if accessLevel < bug.sanitizeAccess(accessLevel) {
			continue
		}
		if bug.Status == BugStatusDup {
			dups = append(dups, bug)
			continue
		}
		uiBug := createUIBug(c, bug, state, managers)
		bugMap[bug.keyHash()] = uiBug
		id := uiBug.ReportingIndex
		if bug.Status == BugStatusFixed {
			id = -1
		} else if len(uiBug.Commits) != 0 {
			id = -2
		}
		groups[id] = append(groups[id], uiBug)
	}
	for _, dup := range dups {
		bug := bugMap[dup.DupOf]
		if bug == nil {
			continue // this can be an invalid bug which we filtered above
		}
		mergeUIBug(c, bug, dup)
	}
	var uiGroups []*uiBugGroup
	for index, bugs := range groups {
		sort.Slice(bugs, func(i, j int) bool {
			if bugs[i].Namespace != bugs[j].Namespace {
				return bugs[i].Namespace < bugs[j].Namespace
			}
			if bugs[i].ClosedTime != bugs[j].ClosedTime {
				return bugs[i].ClosedTime.After(bugs[j].ClosedTime)
			}
			return bugs[i].ReportedTime.After(bugs[j].ReportedTime)
		})
		caption, fragment, showPatch, showPatched := "", "", false, false
		switch index {
		case -1:
			caption, showPatch, showPatched = "fixed", true, false
		case -2:
			caption, showPatch, showPatched = "fix pending", false, true
			fragment = ns + "-pending"
		case len(config.Namespaces[ns].Reporting) - 1:
			caption, showPatch, showPatched = "open", false, false
			fragment = ns + "-open"
		default:
			reporting := &config.Namespaces[ns].Reporting[index]
			caption, showPatch, showPatched = reporting.DisplayTitle, false, false
			fragment = ns + "-" + reporting.Name
		}
		uiGroups = append(uiGroups, &uiBugGroup{
			Now:         timeNow(c),
			Caption:     fmt.Sprintf("%v (%v)", caption, len(bugs)),
			Fragment:    fragment,
			Namespace:   ns,
			ShowPatch:   showPatch,
			ShowPatched: showPatched,
			ShowIndex:   index,
			Bugs:        bugs,
		})
	}
	sort.Slice(uiGroups, func(i, j int) bool {
		return uiGroups[i].ShowIndex > uiGroups[j].ShowIndex
	})
	fixedLink := ""
	if !onlyFixed {
		fixedLink = fmt.Sprintf("?fixed=%v", ns)
	}
	cfg := config.Namespaces[ns]
	uiNamespace := &uiBugNamespace{
		Name:       ns,
		Caption:    cfg.DisplayTitle,
		FixedCount: fixedCount,
		FixedLink:  fixedLink,
		Groups:     uiGroups,
	}
	return uiNamespace, nil
}

func loadDupsForBug(c context.Context, r *http.Request, bug *Bug, state *ReportingState, managers []string) (
	*uiBugGroup, error) {
	bugHash := bug.keyHash()
	var dups []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Status=", BugStatusDup).
		Filter("DupOf=", bugHash).
		GetAll(c, &dups)
	if err != nil {
		return nil, err
	}
	var results []*uiBug
	accessLevel := accessLevel(c, r)
	for _, dup := range dups {
		if accessLevel < dup.sanitizeAccess(accessLevel) {
			continue
		}
		results = append(results, createUIBug(c, dup, state, managers))
	}
	group := &uiBugGroup{
		Now:         timeNow(c),
		Caption:     "duplicates",
		ShowPatched: true,
		ShowStatus:  true,
		Bugs:        results,
	}
	return group, nil
}

func loadSimilarBugs(c context.Context, r *http.Request, bug *Bug, state *ReportingState) (*uiBugGroup, error) {
	var similar []*Bug
	_, err := db.NewQuery("Bug").
		Filter("Title=", bug.Title).
		GetAll(c, &similar)
	if err != nil {
		return nil, err
	}
	managers := make(map[string][]string)
	var results []*uiBug
	accessLevel := accessLevel(c, r)
	domain := config.Namespaces[bug.Namespace].SimilarityDomain
	for _, similar := range similar {
		if accessLevel < similar.sanitizeAccess(accessLevel) {
			continue
		}
		if similar.Namespace == bug.Namespace && similar.Seq == bug.Seq {
			continue
		}
		if config.Namespaces[similar.Namespace].SimilarityDomain != domain {
			continue
		}
		if managers[similar.Namespace] == nil {
			mgrs, err := managerList(c, similar.Namespace)
			if err != nil {
				return nil, err
			}
			managers[similar.Namespace] = mgrs
		}
		results = append(results, createUIBug(c, similar, state, managers[similar.Namespace]))
	}
	group := &uiBugGroup{
		Now:           timeNow(c),
		Caption:       "similar bugs",
		ShowNamespace: true,
		ShowPatched:   true,
		ShowStatus:    true,
		Bugs:          results,
	}
	return group, nil
}

func createUIBug(c context.Context, bug *Bug, state *ReportingState, managers []string) *uiBug {
	reportingIdx, status, link := 0, "", ""
	var reported time.Time
	var err error
	if bug.Status == BugStatusOpen {
		_, _, _, _, reportingIdx, status, link, err = needReport(c, "", state, bug)
		reported = bug.Reporting[reportingIdx].Reported
		if err != nil {
			status = err.Error()
		}
		if status == "" {
			status = "???"
		}
	} else {
		for i := range bug.Reporting {
			bugReporting := &bug.Reporting[i]
			if i == len(bug.Reporting)-1 ||
				bug.Status == BugStatusInvalid && !bugReporting.Closed.IsZero() &&
					bug.Reporting[i+1].Closed.IsZero() ||
				(bug.Status == BugStatusFixed || bug.Status == BugStatusDup) &&
					bugReporting.Closed.IsZero() {
				reportingIdx = i
				reported = bugReporting.Reported
				link = bugReporting.Link
				switch bug.Status {
				case BugStatusInvalid:
					status = "closed as invalid"
					if bugReporting.Auto {
						status = "auto-" + status
					}
				case BugStatusFixed:
					status = "fixed"
				case BugStatusDup:
					status = "closed as dup"
				default:
					status = fmt.Sprintf("unknown (%v)", bug.Status)
				}
				status = fmt.Sprintf("%v on %v", status, html.FormatTime(bug.Closed))
				break
			}
		}
	}
	creditEmail, err := email.AddAddrContext(ownEmail(c), bug.Reporting[reportingIdx].ID)
	if err != nil {
		log.Errorf(c, "failed to generate credit email: %v", err)
	}
	id := bug.keyHash()
	uiBug := &uiBug{
		Namespace:      bug.Namespace,
		Title:          bug.displayTitle(),
		BisectCause:    bug.BisectCause > BisectPending,
		NumCrashes:     bug.NumCrashes,
		FirstTime:      bug.FirstTime,
		LastTime:       bug.LastTime,
		ReportedTime:   reported,
		ClosedTime:     bug.Closed,
		ReproLevel:     bug.ReproLevel,
		ReportingIndex: reportingIdx,
		Status:         status,
		Link:           bugLink(id),
		ExternalLink:   link,
		CreditEmail:    creditEmail,
		NumManagers:    len(managers),
	}
	updateBugBadness(c, uiBug)
	if len(bug.Commits) != 0 {
		for i, com := range bug.Commits {
			cfg := config.Namespaces[bug.Namespace]
			info := bug.getCommitInfo(i)
			uiBug.Commits = append(uiBug.Commits, &uiCommit{
				Hash:  info.Hash,
				Title: com,
				Link:  vcs.CommitLink(cfg.Repos[0].URL, info.Hash),
			})
		}
		for _, mgr := range managers {
			found := false
			for _, mgr1 := range bug.PatchedOn {
				if mgr == mgr1 {
					found = true
					break
				}
			}
			if found {
				uiBug.PatchedOn = append(uiBug.PatchedOn, mgr)
			} else {
				uiBug.MissingOn = append(uiBug.MissingOn, mgr)
			}
		}
		sort.Strings(uiBug.PatchedOn)
		sort.Strings(uiBug.MissingOn)
	}
	return uiBug
}

func mergeUIBug(c context.Context, bug *uiBug, dup *Bug) {
	bug.NumCrashes += dup.NumCrashes
	bug.BisectCause = bug.BisectCause || dup.BisectCause > BisectPending
	if bug.LastTime.Before(dup.LastTime) {
		bug.LastTime = dup.LastTime
	}
	if bug.ReproLevel < dup.ReproLevel {
		bug.ReproLevel = dup.ReproLevel
	}
	updateBugBadness(c, bug)
}

func updateBugBadness(c context.Context, bug *uiBug) {
	bug.NumCrashesBad = bug.NumCrashes >= 10000 && timeNow(c).Sub(bug.LastTime) < 24*time.Hour
}

func loadCrashesForBug(c context.Context, bug *Bug) ([]*uiCrash, []byte, error) {
	bugKey := bug.key(c)
	// We can have more than maxCrashes crashes, if we have lots of reproducers.
	crashes, _, err := queryCrashesForBug(c, bugKey, 2*maxCrashes+200)
	if err != nil || len(crashes) == 0 {
		return nil, nil, err
	}
	builds := make(map[string]*Build)
	var results []*uiCrash
	for _, crash := range crashes {
		build := builds[crash.BuildID]
		if build == nil {
			build, err = loadBuild(c, bug.Namespace, crash.BuildID)
			if err != nil {
				return nil, nil, err
			}
			builds[crash.BuildID] = build
		}
		results = append(results, makeUICrash(crash, build))
	}
	sampleReport, _, err := getText(c, textCrashReport, crashes[0].Report)
	if err != nil {
		return nil, nil, err
	}
	return results, sampleReport, nil
}

func makeUICrash(crash *Crash, build *Build) *uiCrash {
	ui := &uiCrash{
		Manager:      crash.Manager,
		Time:         crash.Time,
		Maintainers:  strings.Join(crash.Maintainers, ", "),
		LogLink:      textLink(textCrashLog, crash.Log),
		ReportLink:   textLink(textCrashReport, crash.Report),
		ReproSyzLink: textLink(textReproSyz, crash.ReproSyz),
		ReproCLink:   textLink(textReproC, crash.ReproC),
	}
	if build != nil {
		ui.uiBuild = makeUIBuild(build)
	}
	return ui
}

func makeUIBuild(build *Build) *uiBuild {
	return &uiBuild{
		Time:                build.Time,
		SyzkallerCommit:     build.SyzkallerCommit,
		SyzkallerCommitLink: vcs.LogLink(vcs.SyzkallerRepo, build.SyzkallerCommit),
		SyzkallerCommitDate: build.SyzkallerCommitDate,
		KernelAlias:         kernelRepoInfo(build).Alias,
		KernelCommit:        build.KernelCommit,
		KernelCommitLink:    vcs.LogLink(build.KernelRepo, build.KernelCommit),
		KernelCommitTitle:   build.KernelCommitTitle,
		KernelCommitDate:    build.KernelCommitDate,
		KernelConfigLink:    textLink(textKernelConfig, build.KernelConfig),
	}
}

func loadManagers(c context.Context, accessLevel AccessLevel) ([]*uiManager, error) {
	now := timeNow(c)
	date := timeDate(now)
	managers, managerKeys, err := loadAllManagers(c)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(managers); i++ {
		if accessLevel >= config.Namespaces[managers[i].Namespace].AccessLevel {
			continue
		}
		last := len(managers) - 1
		managers[i] = managers[last]
		managers = managers[:last]
		managerKeys[i] = managerKeys[last]
		managerKeys = managerKeys[:last]
		i--
	}
	var buildKeys []*db.Key
	var statsKeys []*db.Key
	for i, mgr := range managers {
		if mgr.CurrentBuild != "" {
			buildKeys = append(buildKeys, buildKey(c, mgr.Namespace, mgr.CurrentBuild))
		}
		if timeDate(mgr.LastAlive) == date {
			statsKeys = append(statsKeys,
				db.NewKey(c, "ManagerStats", "", int64(date), managerKeys[i]))
		}
	}
	builds := make([]*Build, len(buildKeys))
	if err := db.GetMulti(c, buildKeys, builds); err != nil {
		return nil, err
	}
	uiBuilds := make(map[string]*uiBuild)
	for _, build := range builds {
		uiBuilds[build.Namespace+"|"+build.ID] = makeUIBuild(build)
	}
	stats := make([]*ManagerStats, len(statsKeys))
	if err := db.GetMulti(c, statsKeys, stats); err != nil {
		return nil, err
	}
	var fullStats []*ManagerStats
	for _, mgr := range managers {
		if timeDate(mgr.LastAlive) != date {
			fullStats = append(fullStats, &ManagerStats{})
			continue
		}
		fullStats = append(fullStats, stats[0])
		stats = stats[1:]
	}
	var results []*uiManager
	for i, mgr := range managers {
		stats := fullStats[i]
		link := mgr.Link
		if accessLevel < AccessUser {
			link = ""
		}
		results = append(results, &uiManager{
			Now:                   timeNow(c),
			Namespace:             mgr.Namespace,
			Name:                  mgr.Name,
			Link:                  link,
			CoverLink:             config.CoverPath + mgr.Name + ".html",
			CurrentBuild:          uiBuilds[mgr.Namespace+"|"+mgr.CurrentBuild],
			FailedBuildBugLink:    bugLink(mgr.FailedBuildBug),
			FailedSyzBuildBugLink: bugLink(mgr.FailedSyzBuildBug),
			LastActive:            mgr.LastAlive,
			LastActiveBad:         now.Sub(mgr.LastAlive) > 6*time.Hour,
			CurrentUpTime:         mgr.CurrentUpTime,
			MaxCorpus:             stats.MaxCorpus,
			MaxCover:              stats.MaxCover,
			TotalFuzzingTime:      stats.TotalFuzzingTime,
			TotalCrashes:          stats.TotalCrashes,
			TotalExecs:            stats.TotalExecs,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].Namespace != results[j].Namespace {
			return results[i].Namespace < results[j].Namespace
		}
		return results[i].Name < results[j].Name
	})
	return results, nil
}

func loadRecentJobs(c context.Context) ([]*uiJob, error) {
	var jobs []*Job
	keys, err := db.NewQuery("Job").
		Order("-Created").
		Limit(40).
		GetAll(c, &jobs)
	if err != nil {
		return nil, err
	}
	var results []*uiJob
	for i, job := range jobs {
		results = append(results, makeUIJob(job, keys[i], nil, nil))
	}
	return results, nil
}

func makeUIJob(job *Job, jobKey *db.Key, crash *Crash, build *Build) *uiJob {
	ui := &uiJob{
		Type:            job.Type,
		Created:         job.Created,
		BugLink:         bugLink(jobKey.Parent().StringID()),
		ExternalLink:    job.Link,
		User:            job.User,
		Reporting:       job.Reporting,
		Namespace:       job.Namespace,
		Manager:         job.Manager,
		BugTitle:        job.BugTitle,
		KernelAlias:     kernelRepoInfoRaw(job.Namespace, job.KernelRepo, job.KernelBranch).Alias,
		PatchLink:       textLink(textPatch, job.Patch),
		Attempts:        job.Attempts,
		Started:         job.Started,
		Finished:        job.Finished,
		CrashTitle:      job.CrashTitle,
		CrashLogLink:    textLink(textCrashLog, job.CrashLog),
		CrashReportLink: textLink(textCrashReport, job.CrashReport),
		LogLink:         textLink(textLog, job.Log),
		ErrorLink:       textLink(textError, job.Error),
	}
	if !job.Finished.IsZero() {
		ui.Duration = job.Finished.Sub(job.Started)
	}
	for _, com := range job.Commits {
		ui.Commits = append(ui.Commits, &uiCommit{
			Hash:   com.Hash,
			Title:  com.Title,
			Author: fmt.Sprintf("%v <%v>", com.AuthorName, com.Author),
			CC:     strings.Split(com.CC, "|"),
			Date:   com.Date,
		})
	}
	if len(ui.Commits) == 1 {
		ui.Commit = ui.Commits[0]
		ui.Commits = nil
	}
	if crash != nil {
		ui.Crash = makeUICrash(crash, build)
	}
	return ui
}

func fetchErrorLogs(c context.Context) ([]byte, error) {
	const (
		minLogLevel  = 3
		maxLines     = 100
		maxLineLen   = 1000
		reportPeriod = 7 * 24 * time.Hour
	)
	q := &log.Query{
		StartTime:     time.Now().Add(-reportPeriod),
		AppLogs:       true,
		ApplyMinLevel: true,
		MinLevel:      minLogLevel,
	}
	result := q.Run(c)
	var lines []string
	for i := 0; i < maxLines; i++ {
		rec, err := result.Next()
		if rec == nil {
			break
		}
		if err != nil {
			entry := fmt.Sprintf("ERROR FETCHING LOGS: %v\n", err)
			lines = append(lines, entry)
			break
		}
		for _, al := range rec.AppLogs {
			if al.Level < minLogLevel {
				continue
			}
			text := strings.Replace(al.Message, "\n", " ", -1)
			text = strings.Replace(text, "\r", "", -1)
			if len(text) > maxLineLen {
				text = text[:maxLineLen]
			}
			res := ""
			if !strings.Contains(rec.Resource, "method=log_error") {
				res = fmt.Sprintf(" (%v)", rec.Resource)
			}
			entry := fmt.Sprintf("%v: %v%v\n", al.Time.Format("Jan 02 15:04"), text, res)
			lines = append(lines, entry)
		}
	}
	buf := new(bytes.Buffer)
	for i := len(lines) - 1; i >= 0; i-- {
		buf.WriteString(lines[i])
	}
	return buf.Bytes(), nil
}

func bugLink(id string) string {
	if id == "" {
		return ""
	}
	return "/bug?id=" + id
}
