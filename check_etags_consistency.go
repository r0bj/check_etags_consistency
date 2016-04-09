package main

import (
	"fmt"
	"strings"
	"sort"
	"time"

	"github.com/parnurzeal/gorequest"
	"github.com/olorin/nagiosplugin"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	servers = kingpin.Arg("servers", "comma separated list of HTTP servers").Required().String()
	concurrent = kingpin.Flag("concurrent", "max number of concurrent HTTP requests").Default("100").Short('c').Int()
	timeout = kingpin.Flag("timeout", "timeout for HTTP requests").Default("10").Short('t').Int()
	url = kingpin.Flag("url", "URL").Default("http://stalker.wikia.com/wiki/Main_Page").Short('u').String()
)

type Msg struct {
	host string
	etag interface{}
}

type Pair struct {
	Key string
	Value int
}

type Param struct {
	host string
	url string
}

type PairList []Pair

func (p PairList) Len() int { return len(p) }
func (p PairList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }

func worker(id int, jobs <-chan Param, results chan<- Msg) {
	for j := range jobs {
		var msg Msg
		msg.host = j.host

		proxyUrl := "http://" + j.host + ":80"
		request := gorequest.New().Proxy(proxyUrl).Timeout(time.Duration(*timeout) * time.Second)
		resp, _, err := request.Get(j.url).
			Set("X-Wikia-Internal-Request", `nagios`).
			End()
		if err != nil {
			msg.etag = nil
			results <- msg
			continue
		}
		if resp.StatusCode != 200 {
			msg.etag = nil
			results <- msg
			continue	
		}

		if etag, ok := resp.Header["Etag"]; ok {
			msg.etag = etag[0]
			results <- msg
		} else {
			msg.etag = nil
			results <- msg
		}
	}
}

func executeWorkers(hosts, url string, concurrent int) []Msg {
	hostsList := strings.Split(hosts, ",")

	jobs := make(chan Param, len(hostsList))
	results := make(chan Msg, len(hostsList))

	var workersNum int
	if len(hostsList) < concurrent {
		workersNum = len(hostsList)
	} else {
		workersNum = concurrent
	}
	for w := 1; w <= workersNum; w++ {
		go worker(w, jobs, results)
	}

	for _, h := range hostsList {
		var p Param
		p.host = h
		p.url = url
		jobs <- p
	}
	close(jobs)

	var resultList []Msg
	for r := 1; r <= len(hostsList); r++ {
		resultList = append(resultList, <- results)
	}
	return resultList
}

func analizeResults(messages []Msg, check *nagiosplugin.Check) {
	hostsPerEtag := make(map[string][]string)
	failedHosts := make([]string, 0)
	for _, msg := range messages {
		if msg.etag == nil {
			failedHosts = append(failedHosts, msg.host)
		} else {
			hostsPerEtag[msg.etag.(string)] = append(hostsPerEtag[msg.etag.(string)], msg.host)
		}
	}

	// if there are more than one ETag found
	if len(hostsPerEtag) > 1 {
		numOfEtags := make(map[string]int)
		for k, _ := range hostsPerEtag {
			numOfEtags[k] = len(hostsPerEtag[k])
		}
		sortedNumOfEtags := sortByValue(numOfEtags)
		// delete 0 element of slice
		sortedNumOfEtags = append(sortedNumOfEtags[:0], sortedNumOfEtags[1:]...)

		invalidHosts := make([]string, 0)
		for _, h := range sortedNumOfEtags {
			invalidHosts = append(invalidHosts, hostsPerEtag[h.Key]...)
		}
		check.AddResult(nagiosplugin.CRITICAL, fmt.Sprintf("invalid ETag on: %s", strings.Join(append(invalidHosts, failedHosts...), " ")))
	} else if len(hostsPerEtag) == 0 {
		check.AddResult(nagiosplugin.WARNING, "no ETags")
	} else if len(hostsPerEtag) == 1 {
		var etagsNum int
		for k, _ := range hostsPerEtag {
			etagsNum = len(hostsPerEtag[k])
			break
		}
		if len(failedHosts) == 0 {
			check.AddResult(nagiosplugin.OK, fmt.Sprintf("%d identical ETags", etagsNum))
		} else {
			check.AddResult(nagiosplugin.WARNING, fmt.Sprintf("no ETags from: %s", strings.Join(failedHosts, " ")))
		}
	}
}

func sortByValue(m map[string]int) PairList {
	p := make(PairList, len(m))

	i := 0
	for k, v := range m {
		p[i] = Pair{k, v}
		i++
	}
	sort.Sort(sort.Reverse(p))
	return p
}

func main() {
	kingpin.Parse()

	check := nagiosplugin.NewCheck()
	defer check.Finish()

	analizeResults(executeWorkers(*servers, *url, *concurrent), check)
}
