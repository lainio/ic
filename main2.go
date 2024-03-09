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

	//jsonData := make([]json.RawMessage, 0, 14000)
	var jsonData []json.RawMessage

	try.To(json.NewDecoder(r).Decode(&jsonData))

	println("jsonData len:", len(jsonData))

	duration := time.Since(start)
	fmt.Printf("Unmarshalling took %v\n", duration)
}
