package main

import (
	"fmt"

	"github.com/assignment/config"
	"github.com/assignment/router"
)

func init() {
	fmt.Println("init")
	config.DataMigration()

}

func main() {
	router.HandlerFunc()
}
