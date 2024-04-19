package router

import (
	"log"
	"net/http"

	"github.com/assignment/handler"
)

func HandlerFunc() {

	http.HandleFunc("/signup", handler.SignupHandler)
	http.HandleFunc("/login", handler.LoginHandler)
	http.HandleFunc("/home", handler.HomeHandler)
	http.HandleFunc("/addBook", handler.AddBookHandler)
	http.HandleFunc("/deleteBook", handler.DeleteBookHandler)

	http.HandleFunc("/sign", handler.Signup)
	http.HandleFunc("/log", handler.Login)

	log.Fatal(http.ListenAndServe(":8081", nil))
}
