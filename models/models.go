package models

type User struct {
	Username string `gorm:"unique"`
	Password string
	Email    string
	Type     string
}

type Book struct {
	Name        string
	Author      string
	Publication string
}
