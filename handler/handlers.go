package handler

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/assignment/config"
	"github.com/assignment/models"
	"github.com/dgrijalva/jwt-go"
)

var secretKey = []byte("secret")

// Sample users data
var users = []models.User{
	{Username: "admin", Password: "adminpass", Type: "admin"},
	{Username: "user", Password: "userpass", Type: "regular"},
}

func GenerateJWT(user models.User) (string, string, error) {
	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessToken.Claims = jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Minute * 15).Unix(),
	}

	accessTokenString, err := accessToken.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	refreshToken.Claims = jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	}

	refreshTokenString, err := refreshToken.SignedString(secretKey)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, err
}

func GenerateAccessTokenFromRefreshToken(ExpiredAccessToken string, RefreshToken string) (string, error) {
	var newAccessTokenString string
	token, err := jwt.Parse(ExpiredAccessToken, func(t *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return "", err
	}
	if !token.Valid {
		refreshTokenClaims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(RefreshToken, refreshTokenClaims, func(t *jwt.Token) (interface{}, error) {
			return secretKey, nil
		})
		if err != nil {
			fmt.Println("error in parsing refresh token :", err)
			return "", err
		}
		newAccessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": refreshTokenClaims["username"],
			"exp":      time.Now().Add(time.Hour * 1).Unix(),
		})
		newAccessTokenString, err = newAccessToken.SignedString(secretKey)
		if err != nil {
			fmt.Println("error in signinig new access token :", err)
			return "", err
		}

	} else {
		fmt.Println("Access token is still valid")
	}
	return newAccessTokenString, nil
}

func generateToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24 * 30).Unix(),
	})
	return token.SignedString(secretKey)
}

func verifyToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["username"].(string), nil
	}
	return "", fmt.Errorf("invalid token")
}

func readBooksFile(filename string) ([]models.Book, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	lines, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var books []models.Book
	for _, line := range lines {
		book := models.Book{
			Name:        line[0],
			Author:      line[1],
			Publication: line[2],
		}
		books = append(books, book)
	}

	return books, nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := cookie.Value
	username, err := verifyToken(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var books []models.Book
	if username == "admin" {
		adminBooks, _ := readBooksFile("adminUser.csv")
		books = append(books, adminBooks...)
	}

	regBooks, _ := readBooksFile("regularUser.csv")
	books = append(books, regBooks...)

	for _, book := range books {
		fmt.Fprintf(w, "Book Name: %s\nAuthor: %s\nPublication Year: %d\n\n", book.Name, book.Author, book.Publication)
	}
}

func AddBookHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := cookie.Value
	username, err := verifyToken(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if username != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.ParseForm()
	name := r.Form.Get("name")
	author := r.Form.Get("author")
	publication := r.Form.Get("publication")

	if name == "" || author == "" || publication == "" {
		http.Error(w, "Invalid input parameters", http.StatusBadRequest)
		return
	}

	newBook := models.Book{Name: name, Author: author, Publication: publication}
	file, err := os.OpenFile("regularUser.csv", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	writer.Write([]string{newBook.Name, newBook.Author, newBook.Publication})
	writer.Flush()

	w.WriteHeader(http.StatusCreated)
}

func DeleteBookHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token := cookie.Value
	username, err := verifyToken(token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if username != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.ParseForm()
	name := strings.ToLower(r.Form.Get("name"))

	if name == "" {
		http.Error(w, "Invalid input parameter", http.StatusBadRequest)
		return
	}

	file, err := os.OpenFile("regularUser.csv", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	lines, err := reader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	var updatedLines [][]string
	for _, line := range lines {
		if strings.ToLower(line[0]) != name {
			updatedLines = append(updatedLines, line)
		}
	}

	file.Truncate(0)
	file.Seek(0, 0)

	writer := csv.NewWriter(file)
	writer.WriteAll(updatedLines)
	writer.Flush()

	w.WriteHeader(http.StatusOK)
}

func Signup(w http.ResponseWriter, r *http.Request) {
	config.Tpl.ExecuteTemplate(w, "signup.html", nil)
}

func Login(w http.ResponseWriter, r *http.Request) {
	config.Tpl.ExecuteTemplate(w, "login.html", nil)
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	uname := r.FormValue("username")
	password := r.FormValue("password")
	utype := r.FormValue("usertype")
	email := r.FormValue("email")

	var user models.User
	user.Username = uname
	user.Password = password
	user.Email = email
	user.Type = utype

	if err := config.DB.Create(&user).Error; err != nil {
		http.Error(w, "email already exists", http.StatusBadRequest)
		return
	}
	config.Tpl.ExecuteTemplate(w, "home.html", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// username := r.Form.Get("username")
	// password := r.Form.Get("password")

	username := r.FormValue("username")
	password := r.FormValue("password")

	var user models.User
	err := config.DB.Where("username =  ? && password = ?", username, password).Find(&user).Error
	if err != nil {
		fmt.Println("error in getting user :", err)
		return
	}

	// var userType string
	// for _, user := range users {
	// 	if user.Username == username && user.Password == password {
	// 		userType = user.Type
	// 		break
	// 	}
	// }
	userType := user.Type

	if userType == "" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := generateToken(username)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24 * 30),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	config.Tpl.ExecuteTemplate(w, "home.html", nil)
}
