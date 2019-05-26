// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"bufio"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	//"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type ReportGenerator struct {
	//vmlinux  string
	src     string
	arch    string
	prefix  string
	symbols []symbol
	pcs     map[uint64][]symbolizer.Frame
	//files map[string]uint64
	//coverPCs []uint64
}

type symbol struct {
	start uint64
	end   uint64
	//name  string
	//pcs []symbolizer.Frame
}

type coverage struct {
	line    int
	covered bool
}

func MakeReportGenerator(vmlinux, src, arch string) (*ReportGenerator, error) {
	rg := &ReportGenerator{
		src:  src,
		arch: arch,
		pcs:  make(map[uint64][]symbolizer.Frame),
		//files: make(map[string]uint64),
	}
	errc := make(chan error)
	go func() {
		var err error
		rg.symbols, err = readSymbols(vmlinux)
		errc <- err
	}()
	frames, err := objdumpAndSymbolize(vmlinux, arch)
	if err != nil {
		return nil, err
	}
	if len(frames) == 0 {
		return nil, fmt.Errorf("%v does not have debug info (set CONFIG_DEBUG_INFO=y)", vmlinux)
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	for _, frame := range frames {
		if rg.prefix == "" {
			rg.prefix = frame.File
		} else {
			rg.prefix = combinePrefix(rg.prefix, frame.File)
			if rg.prefix == "" {
				break
			}
		}
	}
	for _, frame := range frames {
		rg.pcs[frame.PC] = append(rg.pcs[frame.PC], frame)
	}
	return rg, nil
}

type file struct {
	lines       map[int]line
	totalPCs    map[uint64]bool
	coverPCs    map[uint64]bool
	totalInline map[int]bool
	coverInline map[int]bool
}

type line struct {
	count         int
	uncovered     bool
	symbolCovered bool
}

func (rg *ReportGenerator) Do(w io.Writer, pcs []uint64) error {
	if len(pcs) == 0 {
		return fmt.Errorf("no coverage data available")
	}
	coveredPCs := make(map[uint64]bool)
	symbols := make(map[uint64]bool)
	files := make(map[string]*file)
	for _, pc := range pcs {
		pc = PreviousInstructionPC(rg.arch, pc)
		symbols[rg.findSymbol(pc)] = true
		frames, ok := rg.pcs[pc]
		if !ok {
			//fmt.Printf("pc=0x%x missing\n", pc)
			continue
		}
		coveredPCs[pc] = true
		for _, frame := range frames {
			f := getFile(files, frame.File)
			if base := filepath.Base(frame.File); base == "binfmt_script.c" {
				fmt.Printf("%v line=%v COVERED\n", base, frame.Line)
			}
			ln := f.lines[frame.Line]
			ln.count++
			f.lines[frame.Line] = ln
		}
	}
	for pc, frames := range rg.pcs {
		covered := coveredPCs[pc]
		for _, frame := range frames {
			f := getFile(files, frame.File)
			if base := filepath.Base(frame.File); base == "binfmt_script.c" {
				fmt.Printf("%v inline=%v line=%v pc 0x%x covered=%v\n", base, frame.Inline, frame.Line, pc, covered)
			}
			if frame.Inline {
				f.totalInline[frame.Line] = true
				if covered {
					f.coverInline[frame.Line] = true
				}
			} else {
				f.totalPCs[pc] = true
				if covered {
					f.coverPCs[pc] = true
				}
			}
			if !covered && frame.Top {
				ln := f.lines[frame.Line]
				ln.uncovered = true
				ln.symbolCovered = symbols[rg.findSymbol(pc)]
				f.lines[frame.Line] = ln
			}
		}
	}
	return rg.generate(w, files)
}

func getFile(files map[string]*file, name string) *file {
	f := files[name]
	if f == nil {
		f = &file{
			lines:       make(map[int]line),
			totalPCs:    make(map[uint64]bool),
			coverPCs:    make(map[uint64]bool),
			totalInline: make(map[int]bool),
			coverInline: make(map[int]bool),
		}
		files[name] = f
	}
	return f
}

func (rg *ReportGenerator) generate(w io.Writer, files map[string]*file) error {
	d := &templateData{
		Root: new(templateDir),
	}
	for fname, file := range files {
		remain := filepath.Clean(strings.TrimPrefix(fname, rg.prefix))
		if rg.src != "" && !strings.HasPrefix(remain, rg.src) {
			fname = filepath.Join(rg.src, remain)
		}
		pos := d.Root
		path := ""
		for {
			if path != "" {
				path += "/"
			}
			sep := strings.IndexByte(remain, filepath.Separator)
			if sep == -1 {
				path += remain
				break
			}
			dir := remain[:sep]
			path += dir
			if pos.Dirs == nil {
				pos.Dirs = make(map[string]*templateDir)
			}
			if pos.Dirs[dir] == nil {
				pos.Dirs[dir] = &templateDir{
					Path: path,
					Name: dir,
				}
			}
			pos = pos.Dirs[dir]
			remain = remain[sep+1:]
		}
		f := &templateFile{
			Path:    path,
			Name:    remain,
			Total:   len(file.totalPCs) + len(file.totalInline),
			Covered: len(file.coverPCs) + len(file.coverInline),
		}
		if f.Total == 0 {
			return fmt.Errorf("%v: file does not have any coverage", fname)
		}
		pos.Files = append(pos.Files, f)
		if len(file.lines) == 0 || f.Covered == 0 {
			continue
		}
		lines, err := parseFile(fname)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		for i, ln := range lines {
			cov, ok := file.lines[i+1]
			class, count := "", "     "
			if ok {
				if cov.count > 0 {
					count = fmt.Sprintf("% 5v", cov.count)
					class = "covered"
					if cov.uncovered {
						class = "both"
					}
				} else {
					class = "weak-uncovered"
					if cov.symbolCovered {
						class = "uncovered"
					}
				}
			}
			buf.WriteString(fmt.Sprintf("<span class='count'>%v</span>", count))
			if class == "" {
				buf.WriteByte(' ')
				buf.Write(ln)
				buf.WriteByte('\n')
			} else {
				buf.WriteString(fmt.Sprintf("<span class='%v'> ", class))
				buf.Write(ln)
				buf.WriteString("</span>\n")
			}
		}
		d.Contents = append(d.Contents, template.HTML(buf.String()))
		f.Index = len(d.Contents) - 1
	}
	processDir(d.Root)
	return coverTemplate.Execute(w, d)
}

func processDir(dir *templateDir) {
	for len(dir.Dirs) == 1 && len(dir.Files) == 0 {
		for _, child := range dir.Dirs {
			dir.Name += "/" + child.Name
			dir.Files = child.Files
			dir.Dirs = child.Dirs
		}
	}
	sort.Slice(dir.Files, func(i, j int) bool {
		return dir.Files[i].Name < dir.Files[j].Name
	})
	for _, f := range dir.Files {
		dir.Total += f.Total
		dir.Covered += f.Covered
		f.Percent = float64(f.Covered) / float64(f.Total) * 100
	}
	for _, child := range dir.Dirs {
		processDir(child)
		dir.Total += child.Total
		dir.Covered += child.Covered
	}
	dir.Percent = float64(dir.Covered) / float64(dir.Total) * 100
	if dir.Covered == 0 {
		dir.Dirs = nil
		dir.Files = nil
	}
}

func (rg *ReportGenerator) findSymbol(pc uint64) uint64 {
	idx := sort.Search(len(rg.symbols), func(i int) bool {
		return pc < rg.symbols[i].end
	})
	if idx == len(rg.symbols) {
		return 0
	}
	s := rg.symbols[idx]
	if pc < s.start || pc > s.end {
		return 0
	}
	return s.start
}

func readSymbols(obj string) ([]symbol, error) {
	raw, err := symbolizer.ReadSymbols(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to run nm on %v: %v", obj, err)
	}
	var symbols []symbol
	for _, ss := range raw {
		for _, s := range ss {
			symbols = append(symbols, symbol{
				start: s.Addr,
				end:   s.Addr + uint64(s.Size),
				//name:  name,
			})
		}
	}
	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].start < symbols[j].start
	})
	return symbols, nil
}

// objdumpAndSymbolize collects list of PCs of __sanitizer_cov_trace_pc calls
// in the kernel and symbolizes them.
func objdumpAndSymbolize(obj, arch string) ([]symbolizer.Frame, error) {
	errc := make(chan error)
	pcchan := make(chan []uint64, 10)
	var frames []symbolizer.Frame
	go func() {
		symb := symbolizer.NewSymbolizer()
		defer symb.Close()
		var err error
		for pcs := range pcchan {
			if err != nil {
				continue
			}
			frames1, err1 := symb.SymbolizeArray(obj, pcs)
			if err1 != nil {
				err = fmt.Errorf("failed to symbolize: %v", err1)
			}
			frames = append(frames, frames1...)
		}
		errc <- err
	}()
	cmd := osutil.Command("objdump", "-d", "--no-show-raw-insn", obj)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to run objdump on %v: %v", obj, err)
	}
	defer cmd.Wait()
	s := bufio.NewScanner(stdout)
	callInsnS, traceFuncS := archCallInsn(arch)
	callInsn, traceFunc := []byte(callInsnS), []byte(traceFuncS)
	var pcs []uint64
	for s.Scan() {
		ln := s.Bytes()
		if pos := bytes.Index(ln, callInsn); pos == -1 {
			//fmt.Printf("LINE=%s (no call)\n", ln)
			continue
		} else if !bytes.Contains(ln[pos:], traceFunc) {
			//fmt.Printf("LINE=%s (no func)\n", ln)
			continue
		}
		for len(ln) != 0 && ln[0] == ' ' {
			ln = ln[1:]
		}
		colon := bytes.IndexByte(ln, ':')
		if colon == -1 {
			//fmt.Printf("LINE=%s (no colon)\n", ln)
			continue
		}
		pc, err := strconv.ParseUint(string(ln[:colon]), 16, 64)
		if err != nil {
			//fmt.Printf("LINE=%s (no int %v)\n", ln, err)
			continue
		}
		//fmt.Printf("PC=0x%x LINE=%s\n", pc, ln)
		pcs = append(pcs, pc)
		if len(pcs) == 100 {
			pcchan <- pcs
			pcs = nil
		}
	}
	if len(pcs) != 0 {
		pcchan <- pcs
	}
	close(pcchan)
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("failed to run objdump output: %v", err)
	}
	if err := <-errc; err != nil {
		return nil, err
	}
	return frames, nil
}

func combinePrefix(prefix, prefix2 string) string {
	i := 0
	for ; i < len(prefix) && i < len(prefix2); i++ {
		if prefix[i] != prefix2[i] {
			break
		}
	}
	return prefix[:i]
}

func parseFile(fn string) ([][]byte, error) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	htmlReplacer := strings.NewReplacer(">", "&gt;", "<", "&lt;", "&", "&amp;", "\t", "        ")
	var lines [][]byte
	for {
		idx := bytes.IndexByte(data, '\n')
		if idx == -1 {
			break
		}
		lines = append(lines, []byte(htmlReplacer.Replace(string(data[:idx]))))
		data = data[idx+1:]
	}
	if len(data) != 0 {
		lines = append(lines, data)
	}
	return lines, nil
}

func PreviousInstructionPC(arch string, pc uint64) uint64 {
	switch arch {
	case "amd64":
		return pc - 5
	case "386":
		return pc - 1
	case "arm64":
		return pc - 4
	case "arm":
		// THUMB instructions are 2 or 4 bytes with low bit set.
		// ARM instructions are always 4 bytes.
		return (pc - 3) & ^uint64(1)
	case "ppc64le":
		return pc - 4
	default:
		panic("unknown arch")
	}
}

func archCallInsn(arch string) (string, string) {
	const callName = " <__sanitizer_cov_trace_pc>"
	switch arch {
	case "amd64":
		// ffffffff8100206a:       callq  ffffffff815cc1d0 <__sanitizer_cov_trace_pc>
		return "\tcallq ", callName
	case "386":
		// c1000102:       call   c10001f0 <__sanitizer_cov_trace_pc>
		return "\tcall ", callName
	case "arm64":
		// ffff0000080d9cc0:       bl      ffff00000820f478 <__sanitizer_cov_trace_pc>
		return "\tbl\t", callName
	case "arm":
		// 8010252c:       bl      801c3280 <__sanitizer_cov_trace_pc>
		return "\tbl\t", callName
	case "ppc64le":
		// c00000000006d904:       bl      c000000000350780 <.__sanitizer_cov_trace_pc>
		return "\tbl ", " <.__sanitizer_cov_trace_pc>"
	default:
		panic("unknown arch")
	}
}

type templateData struct {
	Root     *templateDir
	Contents []template.HTML
}

type templateDir struct {
	Name    string
	Path    string
	Total   int
	Covered int
	Percent float64
	Dirs    map[string]*templateDir
	Files   []*templateFile
}

type templateFile struct {
	Index   int
	Name    string
	Path    string
	Total   int
	Covered int
	Percent float64
}

var coverTemplate = template.Must(template.New("").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>
			.file {
				display: none;
				margin: 0;
				padding: 0;
			}
			.count {
				font-weight: bold;
				border-right: 1px solid #ddd;
				padding-right: 4px;
			}
			.split {
				height: 100%;
				position: fixed;
				z-index: 1;
				top: 0;
				overflow-x: hidden;
			}
			.tree {
				left: 0;
				width: 24%;
			}
			.left {
				border-left: 1px solid #444;
				right: 0;
				width: 76%;
				font-family: 'Courier New', Courier, monospace;
				color: rgb(80, 80, 80);
			}
			.cover {
				float: right;
				width: 120px;
				padding-right: 4px;
			}
			.cover-right {
				float: right;
			}
			.covered {
				color: rgb(0, 0, 0);
				font-weight: bold;
			}
			.uncovered {
				color: rgb(255, 0, 0);
				font-weight: bold;
			}
			.weak-uncovered {
				color: rgb(200, 0, 0);
			}
			.both {
				color: rgb(200, 100, 0);
				font-weight: bold;
			}
			ul, #dir_list {
				list-style-type: none;
				padding-left: 16px;
			}
			#dir_list {
				margin: 0;
				padding: 0;
			}
			.hover:hover {
				background: #ffff99;
			}
			.caret {
				cursor: pointer;
				user-select: none;
			}
			.caret::before {
				color: black;
				content: "\25B6";
				display: inline-block;
				margin-right: 3px;
			}
			.caret-down::before {
				transform: rotate(90deg);
			}
			.nested {
				display: none;
			}
			.active {
				display: block;
			}
		</style>
	</head>
	<body>
		<div class="split tree">
			<ul id="dir_list">
				{{template "dir" .Root}}
			</ul>
		</div>
		<div id="left_pane" class="split left">
			{{range $i, $f := .Contents}}
				<pre class="file" id="contents_{{$i}}">{{$f}}</pre>
			{{end}}
		</div>
	</body>
	<script>
	(function() {
		var toggler = document.getElementsByClassName("caret");
		for (var i = 0; i < toggler.length; i++) {
			toggler[i].addEventListener("click", function() {
				this.parentElement.querySelector(".nested").classList.toggle("active");
				this.classList.toggle("caret-down");
			});
		}
		if (window.location.hash) {
			var hash = decodeURIComponent(window.location.hash.substring(1)).split("/");
			var path = "path";
			for (var i = 0; i < hash.length; i++) {
				path += "/" + hash[i];
				var elem = document.getElementById(path);
				if (elem)
					elem.click();
			}
		}
	})();
	var visible;
	function onFileClick(index) {
		if (visible)
			visible.style.display = 'none';
		visible = document.getElementById("contents_" + index);
		visible.style.display = 'block';
		document.getElementById("left_pane").scrollTo(0, 0);
	}
	</script>
</html>

{{define "dir"}}
	{{range $dir := .Dirs}}
		<li>
			<span id="path/{{$dir.Path}}" class="caret hover">
				{{$dir.Name}}
				<span class="cover hover">
					{{if $dir.Covered}}{{printf "%.1f" $dir.Percent}}%{{else}}---{{end}}
					<span class="cover-right">of {{$dir.Total}}</span>
				</span>
			</span>
			<ul class="nested">
				{{template "dir" $dir}}
			</ul>
		</li>
	{{end}}
	{{range $file := .Files}}
		<li><span class="hover">
			{{if $file.Covered}}
				<a href="#{{$file.Path}}" id="path/{{$file.Path}}" onclick="onFileClick({{$file.Index}})">
					{{$file.Name}}<span class="cover hover">{{printf "%.1f" $file.Percent}}%<span class="cover-right">of {{$file.Total}}</span></span>
				</a>
			{{else}}
					{{$file.Name}}<span class="cover hover">---<span class="cover-right">of {{$file.Total}}</span></span>
			{{end}}
		</span></li>
	{{end}}
{{end}}
`))
