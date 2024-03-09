package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func main() {
	assert.SetDefault(assert.Plain)
	defer err2.Catch(err2.Stderr)

	assert.SLonger(os.Args, 1, "\n\nUsage: %v <json_file>",
		filepath.Base(os.Args[0]))

	start := time.Now()
	filename := os.Args[1]

	r := try.To1(os.Open(filename))

	ready := make(chan struct{})
	ch := make(chan json.RawMessage, 100)
	go func() {
		defer err2.Catch("worker error")

		count := 0
		for d := range ch {
			var item Item
			try.To(json.Unmarshal(d, &item))
			count++
		}
		println("count: ", count)
		ready <- struct{}{}
	}()
	//var jsonData []json.RawMessage

	//try.To(json.NewDecoder(r).Decode(&jsonData))
	dc := json.NewDecoder(r)
	try.To1(dc.Token()) // read '['

	count := 0
	for dc.More() {
		var jsonData json.RawMessage
		//var jsonData Item
		try.To(dc.Decode(&jsonData))
		ch <- jsonData
		count++
	}
	close(ch)

	try.To1(dc.Token()) // read ']'

	//println("jsonData len:", len(jsonData))
	println("data len:", count)

	duration := time.Since(start)
	fmt.Printf("Unmarshalling took %v\n", duration)
	<-ready
}

type Item struct {
	Id    string `json:"id"`
	Type  string `json:"type"`
	Actor struct {
		Id         int    `json:"id"`
		Login      string `json:"login"`
		GravatarId string `json:"gravatar_id"`
		Url        string `json:"url"`
		AvatarUrl  string `json:"avatar_url"`
	} `json:"actor"`
	Repo struct {
		Id   int    `json:"id"`
		Name string `json:"name"`
		Url  string `json:"url"`
	} `json:"repo"`
	Payload struct {
		Ref          string `json:"ref"`
		RefType      string `json:"ref_type"`
		MasterBranch string `json:"master_branch"`
		Description  string `json:"description"`
		PusherType   string `json:"pusher_type"`
	} `json:"payload"`
	Public    bool      `json:"public"`
	CreatedAt time.Time `json:"created_at"`
}
