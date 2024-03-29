// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bsm/histogram/v3"
	"github.com/google/syzkaller/pkg/html/pages"
	"github.com/prometheus/client_golang/prometheus"
)

type UI struct {
	Name  string
	Desc  string
	Link  string
	Level Level
	Value string
	V     int
}

func Create(name, desc string, opts ...any) *Val {
	return global.Create(name, desc, opts...)
}

func Collect(level Level) []UI {
	return global.Collect(level)
}

func RenderHTML() ([]byte, error) {
	return global.RenderHTML()
}

func Import(named map[string]uint64) {
	global.Import(named)
}

var global = newSet(256, true)

type set struct {
	mu           sync.Mutex
	vals         map[string]*Val
	graphs       map[string]*graph
	totalTicks   int
	historySize  int
	historyTicks int
	historyPos   int
	historyScale int
}

type graph struct {
	level   Level
	stacked bool
	lines   map[string]*line
}

type line struct {
	desc string
	rate bool
	data []float64
	hist []*histogram.Histogram
}

const (
	tickPeriod       = time.Second
	histogramBuckets = 255
)

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
		v := val.Val()
		res = append(res, UI{
			Name:  val.name,
			Desc:  val.desc,
			Link:  val.link,
			Level: val.level,
			Value: val.fmt(v, period),
			V:     v,
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
type StackedGraph string

const NoGraph Graph = ""

func LenOf(containerPtr any, mu *sync.RWMutex) func() int {
	v := reflect.ValueOf(containerPtr)
	_ = v.Elem().Len() // panics if container is not slice/map/chan
	return func() int {
		mu.RLock()
		defer mu.RUnlock()
		return v.Elem().Len()
	}
}

func (set *set) Create(name, desc string, opts ...any) *Val {
	val := &Val{
		name:  name,
		desc:  desc,
		graph: name,
		fmt:   func(v int, period time.Duration) string { return fmt.Sprint(v) },
	}
	stacked := false
	for _, o := range opts {
		switch opt := o.(type) {
		case Level:
			val.level = opt
		case Link:
			val.link = string(opt)
		case Graph:
			val.graph = string(opt)
		case StackedGraph:
			val.graph = string(opt)
			stacked = true
		case Rate:
			val.rate = true
			val.fmt = formatRate
		case Distribution:
			val.hist = true
		case func() int:
			val.ext = opt
		case func(int, time.Duration) string:
			val.fmt = opt
		case Prometheus:
			// Prometheus Instrumentation https://prometheus.io/docs/guides/go-application.
			prometheus.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
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
		if stacked {
			set.graphs[val.graph].stacked = true
		}
	}
	return val
}

type Val struct {
	name    string
	desc    string
	link    string
	graph   string
	level   Level
	v       atomic.Uint64
	ext     func() int
	fmt     func(int, time.Duration) string
	rate    bool
	hist    bool
	prev    int
	histMu  sync.Mutex
	histVal *histogram.Histogram
}

func (val *Val) Add(v int) {
	if val.ext != nil {
		panic(fmt.Sprintf("stat %v is in external mode", val.name))
	}
	if val.hist {
		val.histMu.Lock()
		if val.histVal == nil {
			val.histVal = histogram.New(histogramBuckets)
		}
		val.histVal.Add(float64(v))
		val.histMu.Unlock()
		return
	}
	val.v.Add(uint64(v))
}

func (val *Val) Val() int {
	if val.ext != nil {
		return val.ext()
	}
	if val.hist {
		val.histMu.Lock()
		defer val.histMu.Unlock()
		if val.histVal == nil {
			return 0
		}
		return int(val.histVal.Mean())
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

func (set *set) tick() {
	set.mu.Lock()
	defer set.mu.Unlock()

	if set.historyPos == set.historySize {
		set.compress()
	}

	set.totalTicks++
	set.historyTicks++
	for _, val := range set.vals {
		if val.graph == "" {
			continue
		}
		graph := set.graphs[val.graph]
		ln := graph.lines[val.name]
		if ln == nil {
			ln = &line{
				desc: val.desc,
				rate: val.rate,
			}
			if val.hist {
				ln.hist = make([]*histogram.Histogram, set.historySize)
			} else {
				ln.data = make([]float64, set.historySize)
			}
			graph.lines[val.name] = ln
		}
		if val.hist {
			if set.historyTicks == set.historyScale {
				val.histMu.Lock()
				ln.hist[set.historyPos] = val.histVal
				val.histVal = nil
				val.histMu.Unlock()
			}
		} else {
			v := val.Val()
			pv := &ln.data[set.historyPos]
			if val.rate {
				*pv += float64(v-val.prev) / float64(set.historyScale)
				val.prev = v
			} else {
				if *pv < float64(v) {
					*pv = float64(v)
				}
			}
		}
	}
	if set.historyTicks != set.historyScale {
		return
	}
	set.historyTicks = 0
	set.historyPos++
}

func (set *set) compress() {
	half := set.historySize / 2
	set.historyPos = half
	set.historyScale *= 2
	for _, graph := range set.graphs {
		for _, line := range graph.lines {
			for i := 0; i < half; i++ {
				if line.hist != nil {
					h1, h2 := line.hist[2*i], line.hist[2*i+1]
					line.hist[2*i], line.hist[2*i+1] = nil, nil
					line.hist[i] = h1
					if h1 == nil {
						line.hist[i] = h2
					}
				} else {
					v1, v2 := line.data[2*i], line.data[2*i+1]
					line.data[2*i], line.data[2*i+1] = 0, 0
					if line.rate {
						line.data[i] = (v1 + v2) / 2
					} else {
						line.data[i] = v1
						if v2 > v1 {
							line.data[i] = v2
						}
					}
				}
			}
		}
	}
}

func (set *set) RenderHTML() ([]byte, error) {
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
			if ln.hist == nil {
				g.Lines = append(g.Lines, name+": "+ln.desc)
				for i := 0; i < set.historyPos; i++ {
					g.Points[i].Y = append(g.Points[i].Y, ln.data[i])
				}
			} else {
				for _, percent := range []int{10, 50, 90} {
					g.Lines = append(g.Lines, fmt.Sprintf("%v%%", percent))
					for i := 0; i < set.historyPos; i++ {
						v := 0.0
						if ln.hist[i] != nil {
							v = ln.hist[i].Quantile(float64(percent) / 100)
						}
						g.Points[i].Y = append(g.Points[i].Y, v)
					}
				}
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
					hAxis: {minValue: 1, textPosition: 'out', maxAlternation: 1, gridlines: {multiple: 1},
						minorGridlines: {multiple: 1}},
				})
		});
	</script>
{{end}}
</body>
</html>
`)
