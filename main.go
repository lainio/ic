package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const iterations = 1

func main() {
	filename := "large-file.json"
	// Adjust the number of iterations as needed

	start := time.Now() // Start the timer

	// Read the JSON file outside of the timing loop
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("failed to read file: %v\n", err)
		return
	}

	for i := 0; i < iterations; i++ {
		//var jsonData []json.RawMessage
		//var jsonData map[string]interface{} // Use this instead if the JSON root is an object
		var jsonData []Item
		if err := json.Unmarshal(data, &jsonData); err != nil {
			fmt.Printf("failed to unmarshal json: %v\n", err)
			return
		}
		println("jsonData len:", len(jsonData))
	}

	duration := time.Since(start)
	fmt.Printf("Unmarshalling took %v for %d iterations\n", duration, iterations)
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
