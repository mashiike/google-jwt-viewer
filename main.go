package main

import (
	"context"
	"crypto/rand"
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/fujiwara/ridge"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	jwt "github.com/dgrijalva/jwt-go"
)

//go:embed static/*
var staticFS embed.FS

func main() {
	log.Println("[info] checking self IP address")
	resp, err := http.Get("http://checkip.amazonaws.com/")
	if err != nil {
		log.Println("[warn]", err)
	} else {
		io.Copy(os.Stderr, resp.Body)
		resp.Body.Close()
	}
	c := newController()
	router := mux.NewRouter()
	router.Use(accessLogginMiddleware)
	router.HandleFunc("/", c.handleIndex).Methods(http.MethodGet)
	router.HandleFunc("/oauth2/idpresponse", c.handleIDPResponse)
	router.HandleFunc("/view", c.handleView).Methods(http.MethodGet)
	router.PathPrefix("/static/").Handler(http.FileServer(http.FS(staticFS))).Methods(http.MethodGet)
	ridge.Run(":8000", "/", router)
}

//go:embed templates/*
var templateFS embed.FS

type controller struct {
	conf     *oauth2.Config
	endpoint string
	view     *template.Template
}

func newController() *controller {
	view := template.New("view.html")
	view = view.Funcs(
		template.FuncMap{
			"unix_to_time": func(u int64) time.Time {
				return time.Unix(1622426197, 0).Local()
			},
		},
	)
	view = template.Must(view.ParseFS(templateFS, "templates/view.html"))

	endpoint := os.Getenv("ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8000"
	}
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"openid", "email"},
		RedirectURL:  fmt.Sprintf("%s/oauth2/idpresponse", endpoint),
		Endpoint:     google.Endpoint,
	}
	return &controller{
		conf:     conf,
		endpoint: endpoint,
		view:     view,
	}
}

const (
	sessionCookieName string = "oauth2_session"
	idTokenCookieName string = "id_token"
)

func (c *controller) handleIndex(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())
	nonce, err := randStr(20)
	if err != nil {
		log.Printf("[error][%s] %s", reqID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	securityToken, err := randStr(10)
	if err != nil {
		log.Printf("[error][%s] %s", reqID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	auchCodeURL := c.conf.AuthCodeURL(
		c.getState(securityToken),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", "login"),
	)
	http.SetCookie(w, &http.Cookie{
		Name:    sessionCookieName,
		Value:   securityToken,
		Path:    "/",
		Expires: time.Now().Add(10 * time.Minute),
	})
	http.Redirect(w, r, auchCodeURL, http.StatusFound)
}

func (c *controller) getState(securityToken string) string {
	return url.Values{
		"security_token": []string{securityToken},
		"url":            []string{c.endpoint},
	}.Encode()
}

func (c *controller) handleIDPResponse(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())
	securityTokenCookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		log.Printf("[error][%s] Cookie %s can not get: %s", reqID, sessionCookieName, err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	securityToken := securityTokenCookie.Value
	securityTokenCookie.MaxAge = -1
	http.SetCookie(w, securityTokenCookie)
	if r.URL.Query().Get("state") != c.getState(securityToken) {
		log.Printf("[error][%s] state mismatch", reqID)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("[error][%s] code not found", reqID)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	tok, err := c.conf.Exchange(r.Context(), code)
	if err != nil {
		log.Printf("[error][%s] %s", reqID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	idToken, ok := tok.Extra("id_token").(string)
	if !ok {
		log.Printf("[error][%s] id_token can not get", reqID)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    idTokenCookieName,
		Value:   idToken,
		Path:    "/",
		Expires: time.Now().Add(60 * time.Minute),
	})
	http.Redirect(w, r, c.endpoint+"/view", http.StatusFound)
}

type customClaims struct {
	Email      string `json:"email"`
	EmailValid bool   `json:"email_valid"`
	jwt.StandardClaims
}

func (c *controller) handleView(w http.ResponseWriter, r *http.Request) {
	reqID := getRequestID(r.Context())
	idTokenCookie, err := r.Cookie(idTokenCookieName)
	if err != nil {
		log.Printf("[info][%s] Cookie %s can not get and redirect index for login: %s", reqID, idTokenCookieName, err.Error())
		http.Redirect(w, r, c.endpoint, http.StatusFound)
		return
	}
	idToken := idTokenCookie.Value
	idTokenCookie.MaxAge = -1
	http.SetCookie(w, idTokenCookie)

	parser := &jwt.Parser{}
	token, _, err := parser.ParseUnverified(idToken, &customClaims{})
	if err != nil {
		log.Printf("[error][%s] %s", reqID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	err = c.view.Execute(w, map[string]interface{}{
		"IDToken": idToken,
		"Claims":  token.Claims,
	})
	if err != nil {
		log.Printf("[error][%s] %s", reqID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

type contextKey string

const reqIDCtxKey contextKey = "__request_id"

func accessLogginMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := "-"
		if id := r.Header.Get("x-request-id"); id != "" {
			reqID = id
		} else if id := r.Header.Get("x-amz-cf-id"); id != "" {
			reqID = id
		} else if id := r.Header.Get("x-amzn-rrace-id"); id != "" {
			reqID = id
		}
		ctx := context.WithValue(r.Context(), reqIDCtxKey, reqID)
		reqURL := *r.URL
		reqURL.RawQuery = ""
		log.Printf("[info][%s] %s %s", reqID, r.Method, reqURL.String())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getRequestID(ctx context.Context) string {
	val := ctx.Value(reqIDCtxKey)
	if reqID, ok := val.(string); ok {
		return reqID
	}
	return "-"
}

func randStr(digit uint32) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, digit)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand failed:%w", err)
	}
	var result string
	for _, v := range b {
		result += string(letters[int(v)%len(letters)])
	}
	return result, nil
}
