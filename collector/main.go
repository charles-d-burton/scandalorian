package main

import (
	"github.com/charles-d-burton/kanscan/shared"
	"log"
)

//RecordResult interface to define backends for use saving results
type RecordResult interface {
	Create(result *shared.Scan) (bool, error)
	Update(result *shared.Scan) (bool, error)
	Delete(path *shared.Scan) (bool, error)
}

func main() {
	log.Println("Start Collector")
}
