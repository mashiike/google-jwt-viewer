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
	"path/filepath"
	"strings"
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
	c, err := newController()
	if err != nil {
		log.Fatalln(err)
	}
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
	views    map[string]*template.Template
}

func newController() (*controller, error) {
	funcMap := template.FuncMap{
		"unix_to_time": func(u int64) time.Time {
			return time.Unix(u, 0).Local()
		},
	}
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	views := make(map[string]*template.Template, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		log.Printf("[debug] try read templates/%s ...", name)
		view := template.New(entry.Name())
		view = view.Funcs(funcMap)
		view = template.Must(view.ParseFS(templateFS, filepath.Join("templates", name)))
		views[name] = view
	}

	endpoint := os.Getenv("ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8000"
	}
	log.Printf("[info] endpoint is %s\n", endpoint)

	oauth2Endpoint := oauth2.Endpoint{
		AuthURL:   os.Getenv("OAUTH2_AUTHORIZE_ENDPOINT"),
		TokenURL:  os.Getenv("OAUTH2_TOKEN_ENDPOINT"),
		AuthStyle: oauth2.AuthStyleAutoDetect,
	}
	if oauth2Endpoint.AuthURL == "" || oauth2Endpoint.TokenURL == "" {
		log.Println("[info] use google authorization")
		oauth2Endpoint = google.Endpoint
	} else {
		log.Println("[info] use custom authorization")
	}
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"openid", "email"},
		RedirectURL:  fmt.Sprintf("%s/oauth2/idpresponse", endpoint),
		Endpoint:     oauth2Endpoint,
	}
	return &controller{
		conf:     conf,
		endpoint: endpoint,
		views:    views,
	}, nil
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
	Nonce      string `json:"nonce"`
	jwt.StandardClaims
}

func (c *controller) writeView(w http.ResponseWriter, r *http.Request, viewName string, data interface{}) {
	reqID := getRequestID(r.Context())
	view, ok := c.views[viewName]
	if !ok {
		log.Printf("[error] view `%s` not found.\n", viewName)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := view.Execute(w, data); err != nil {
		log.Printf("[error][%s] %s", reqID, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
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
	c.writeView(w, r, "view.html",
		map[string]interface{}{
			"IDToken": idToken,
			"Claims":  token.Claims,
		},
	)
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
