package config

import (
	"fmt"
	"html/template"

	"github.com/assignment/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB
var err error
var Tpl *template.Template

func DataMigration() {
	Tpl = template.Must(template.ParseGlob("templates/*.html"))
	urlDsn := "root:rootwdp@tcp(localhost:3306)/practice"
	DB, err = gorm.Open(mysql.Open(urlDsn), &gorm.Config{})
	if err != nil {
		fmt.Println("error in connection :", err)
		return
	}
	DB.AutoMigrate(models.User{})
}
