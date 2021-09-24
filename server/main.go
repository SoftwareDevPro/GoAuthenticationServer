package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "postgres"
	dbname   = "godb"
)

type Credentials struct {
	Password string `json:"password",db:"password"`
	Username string `json:"username",db:"username"`
}

func main() {
	router := mux.NewRouter()

	// "Login" and "Signup" are handler that we will implement
	router.HandleFunc("/login", Login)
	router.HandleFunc("/signup", Signup)

	// initialize our database connection
	initDB()

	log.Fatal(http.ListenAndServe(":8080", router))
}

func initDB() {
	var err error

	psqInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)

	db, err = sql.Open("postgres", psqInfo)
	if err != nil {
		panic(err)
	}

}

func Signup(w http.ResponseWriter, r *http.Request) {

	creds := &Credentials{}

	err := json.NewDecoder(r.Body).Decode(creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)

	_, err = db.Query("insert into users values ($1, $2)", creds.Username, string(hashedPassword))

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Sign-Up Successful")
}

func Login(w http.ResponseWriter, r *http.Request) {

	creds := &Credentials{}

	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result := db.QueryRow("select password from users where username=$1", creds.Username)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	storedCreds := &Credentials{}

	err = result.Scan(&storedCreds.Password)

	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Login Unauthorized: user not found")
			return
		}
	}

	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	fmt.Fprintln(w, "User Logged In")
}
