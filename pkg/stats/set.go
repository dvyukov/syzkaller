// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsm/histogram/v3"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type UI struct {
	Name  string
	Desc  string
	Link  string
	Level Level
	Value string
}

func Create(name, desc string, opts ...any) *Val {
	return global.Create(name, desc, opts...)
}

func Collect(level Level) []UI {
	return global.Collect(level)
}

func RenderHtml() ([]byte, error) {
	return global.RenderHtml()
}

func StackedGraph(name string) {
	global.StackedGraph(name)
}

/*
func Export() Exported {
	return global.Export()
}

func Import(exp Exported) {
	global.Import(exp)
}
*/

func Import(named map[string]uint64) {
	global.Import(named)
}

var global = newSet(256, true)

type set struct {
	mu           sync.Mutex
	vals         map[string]*Val
	totalTicks   int
	historySize  int
	historyTicks int
	historyPos   int
	historyScale int
	graphs       map[string]*graph
}

type graph struct {
	level   Level
	stacked bool
	lines   map[string]*line
}

type line struct {
	rate bool
	data []float64
}

const tickPeriod = time.Second

func newSet(histSize int, tick bool) *set {
	set := &set{
		vals:         make(map[string]*Val),
		historySize:  histSize,
		historyScale: 1,
		graphs:       make(map[string]*graph),
	}
	if tick {
		go func() {
			for range time.NewTicker(tickPeriod).C {
				set.tick()
			}
		}()
	}
	return set
}

func (set *set) Collect(level Level) []UI {
	set.mu.Lock()
	defer set.mu.Unlock()
	period := time.Duration(set.totalTicks) * tickPeriod
	if period == 0 {
		period = time.Second
	}
	var res []UI
	for _, val := range set.vals {
		if val.level < level {
			continue
		}
		res = append(res, UI{
			Name:  val.name,
			Desc:  val.desc,
			Link:  val.link,
			Level: val.level,
			Value: val.fmt(val.Val(), period),
		})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Level != res[j].Level {
			return res[i].Level > res[j].Level
		}
		return res[i].Name < res[j].Name
	})
	return res
}

func (set *set) Import(named map[string]uint64) {
	set.mu.Lock()
	defer set.mu.Unlock()
	for name, v := range named {
		val := set.vals[name]
		if val == nil {
			panic(fmt.Sprintf("imported stat %v is missing", name))
		}
		val.Add(int(v))
	}
}

func (set *set) tick() {
	set.mu.Lock()
	defer set.mu.Unlock()
	set.totalTicks++

	if set.historyPos == set.historySize {
		set.historyScale *= 2
		half := set.historySize / 2
		set.historyPos = half
		for _, graph := range set.graphs {
			for _, line := range graph.lines {
				for i := 0; i < half; i++ {
					if line.rate {
						line.data[i] = (line.data[2*i] + line.data[2*i+1]) / 2
					} else {
						line.data[i] = line.data[2*i]
						if v := line.data[2*i+1]; line.data[i] < v {
							line.data[i] = v
						}
					}
				}
				clear(line.data[half:])
			}
		}
	}

	for _, val := range set.vals {
		if val.graph == "" {
			continue
		}
		graph := set.graphs[val.graph]
		if val.hist == nil {
			ln := graph.lines[val.name]
			if ln == nil {
				ln = &line{
					rate: val.rate,
					data: make([]float64, set.historySize),
				}
				graph.lines[val.name] = ln
			}
			v := val.Val()
			vf := float64(v)
			pv := &ln.data[set.historyPos]
			if val.rate {
				*pv += (vf - float64(val.prev)) / float64(set.historyScale)
				val.prev = v
			} else {
				if *pv < vf {
					*pv = vf
				}
			}
		} else {
			val.histMu.Lock()
			for _, percent := range []int{10, 50, 90} {
				name := fmt.Sprintf("%v%%", percent)
				ln := graph.lines[name]
				if ln == nil {
					ln = &line{
						data: make([]float64, set.historySize),
					}
					graph.lines[name] = ln
				}
				v := val.hist.Quantile(float64(percent) / 100)
				pv := &ln.data[set.historyPos]
				if *pv < v {
					*pv = v
				}
			}
			val.histMu.Unlock()
		}
	}
	set.historyTicks++
	if set.historyTicks != set.historyScale {
		return
	}
	set.historyTicks = 0
	set.historyPos++
}

type Level int

const (
	All Level = iota
	Simple
	Console
)

type Link string
type Prometheus string
type Rate struct{}
type Distribution struct{}
type Graph string

const NoGraph Graph = ""

func (set *set) Create(name, desc string, opts ...any) *Val {
	val := &Val{
		name:  name,
		desc:  desc,
		graph: name,
		fmt:   func(v int, period time.Duration) string { return fmt.Sprint(v) },
	}
	for _, o := range opts {
		switch opt := o.(type) {
		case Level:
			val.level = opt
		case Link:
			val.link = string(opt)
		case Graph:
			val.graph = string(opt)
		case Rate:
			val.rate = true
			val.fmt = formatRate
		case Distribution:
			val.hist = histogram.New(255)
		case func() int:
			val.ext = opt
		case func(int, time.Duration) string:
			val.fmt = opt
		case Prometheus:
			// Prometheus Instrumentation https://prometheus.io/docs/guides/go-application.
			prometheus.Register(promauto.NewGaugeFunc(prometheus.GaugeOpts{
				Name: string(opt),
				Help: desc,
			},
				func() float64 { return float64(val.Val()) },
			))
		default:
			panic(fmt.Sprintf("unknown stats option %#v", o))
		}
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.vals[name] != nil {
		panic(fmt.Sprintf("duplicate stat %v", name))
	}
	set.vals[name] = val
	if val.graph != "" {
		if set.graphs[val.graph] == nil {
			set.graphs[val.graph] = &graph{
				lines: make(map[string]*line),
			}
		}
		if set.graphs[val.graph].level < val.level {
			set.graphs[val.graph].level = val.level
		}
	}
	return val
}

type Val struct {
	name  string
	desc  string
	link  string
	graph string
	level Level
	v     atomic.Uint64
	ext   func() int
	fmt   func(int, time.Duration) string
	rate  bool
	//imported bool
	prev int
	//exportPrev int
	histMu sync.Mutex
	hist   *histogram.Histogram
}

func (val *Val) Add(v int) {
	if val.ext != nil {
		panic(fmt.Sprintf("stat %v is in external mode", val.name))
	}
	if val.hist != nil {
		val.histMu.Lock()
		val.hist.Add(float64(v))
		val.histMu.Unlock()
		return
	}
	val.v.Add(uint64(v))
}

func (val *Val) Val() int {
	if val.ext != nil {
		return val.ext()
	}
	if val.hist != nil {
		val.histMu.Lock()
		defer val.histMu.Unlock()
		if val.hist.NumBins() == 0 {
			return 0
		}
		return int(val.hist.Mean())
	}
	return int(val.v.Load())
}

func formatRate(v int, period time.Duration) string {
	secs := int(period.Seconds())
	if x := v / secs; x >= 10 {
		return fmt.Sprintf("%v (%v/sec)", v, x)
	}
	if x := v * 60 / secs; x >= 10 {
		return fmt.Sprintf("%v (%v/min)", v, x)
	}
	x := v * 60 * 60 / secs
	return fmt.Sprintf("%v (%v/hour)", v, x)
}

/*
type Exported []exported

type exported struct {
	Name string
	Val  int
}

func (set *set) Export() Exported {
	set.mu.Lock()
	defer set.mu.Unlock()
	res := make(Exported, 0, len(set.vals))
	for _, val := range set.vals {
		if val.hist != nil || val.ext != nil {
			panic(fmt.Sprintf("export of histogram/external stats is not supported: %v", val.name))
		}
		v := int(val.v.Load())
		res = append(res, exported{val.name, v - val.exportPrev})
		val.exportPrev = v
	}
	return res
}

func (set *set) Import(exp Exported) {
	set.mu.Lock()
	defer set.mu.Unlock()
	for _, e := range exp {
		val := set.vals[e.Name]
		if val == nil {
			panic(fmt.Sprintf("imported stat %v is missing", e.Name))
		}
		if val.hist != nil || val.ext != nil {
			panic(fmt.Sprintf("import of histogram/external stats is not supported: %v", e.Name))
		}
		val.imported = true
		val.v.Add(uint64(e.Val))
	}
}
*/

func (set *set) RenderHtml() ([]byte, error) {
	set.mu.Lock()
	defer set.mu.Unlock()
	type Point struct {
		X int
		Y []float64
	}
	type Graph struct {
		ID      int
		Title   string
		Stacked bool
		Level   Level
		Lines   []string
		Points  []Point
	}
	var graphs []Graph
	tick := set.historyScale * int(tickPeriod.Seconds())
	for title, graph := range set.graphs {
		if len(graph.lines) == 0 {
			continue
		}
		g := Graph{
			ID:      len(graphs),
			Title:   title,
			Stacked: graph.stacked,
			Level:   graph.level,
			Points:  make([]Point, set.historyPos),
		}

		for i := 0; i < set.historyPos; i++ {
			g.Points[i].X = i * tick
		}
		for name, ln := range graph.lines {
			g.Lines = append(g.Lines, name)
			for i := 0; i < set.historyPos; i++ {
				g.Points[i].Y = append(g.Points[i].Y, ln.data[i])
			}
		}
		graphs = append(graphs, g)
	}
	sort.Slice(graphs, func(i, j int) bool {
		if graphs[i].Level != graphs[j].Level {
			return graphs[i].Level > graphs[j].Level
		}
		return graphs[i].Title < graphs[j].Title
	})
	buf := new(bytes.Buffer)
	err := htmlTemplate.Execute(buf, graphs)
	return buf.Bytes(), err
}

func (set *set) StackedGraph(name string) {
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.graphs[name] == nil {
		set.graphs[name] = &graph{
			lines: make(map[string]*line),
		}
	}
	set.graphs[name].stacked = true
}

var htmlTemplate = pages.Create(`
<!doctype html>
<html>
<head>
	<title>syzkaller stats</title>
	<script type="text/javascript" src="https://www.google.com/jsapi"></script>
	{{HEAD}}
</head>
<body>
{{range $g := .}}
	<div id="div_{{$g.ID}}"></div>
	<script type="text/javascript">
		google.load("visualization", "1", {packages:["corechart"]});
		google.setOnLoadCallback(function() {
			new google.visualization. {{if $g.Stacked}} AreaChart {{else}} LineChart {{end}} (
				document.getElementById('div_{{$g.ID}}')).
				draw(google.visualization.arrayToDataTable([
					["-" {{range $line := $g.Lines}} , '{{$line}}' {{end}}],
					{{range $p := $g.Points}} [ {{$p.X}} {{range $y := $p.Y}} , {{$y}} {{end}} ], {{end}}
				]), {
					title: '{{$g.Title}}',
					titlePosition: 'in',
					width: "95%",
					height: "400",
					chartArea: {width: '95%', height: '85%'},
					legend: {position: 'in'},
					lineWidth: 2,
					focusTarget: "category",
					{{if $g.Stacked}} isStacked: true, {{end}}
					vAxis: {minValue: 1, textPosition: 'in', gridlines: {multiple: 1}, minorGridlines: {multiple: 1}},
					hAxis: {minValue: 1, textPosition: 'out', maxAlternation: 1, gridlines: {multiple: 1}, minorGridlines: {multiple: 1}},
				})
		});
	</script>
{{end}}
</body>
</html>
`)
