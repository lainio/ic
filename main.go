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

	// Read the JSON file outside of the timing loop
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("failed to read file: %v\n", err)
		return
	}

	start := time.Now() // Start the timer

	for i := 0; i < iterations; i++ {
		//jsonData := make([]json.RawMessage, 0, 14000) 
		var jsonData []json.RawMessage
		// var jsonData map[string]interface{} // Use this instead if the JSON root is an object
		if err := json.Unmarshal(data, &jsonData); err != nil {
			fmt.Printf("failed to unmarshal json: %v\n", err)
			return
		}
		println("jsonData len:", len(jsonData))
	}

	duration := time.Since(start)
	fmt.Printf("Unmarshalling took %v for %d iterations\n", duration, iterations)
}
