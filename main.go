package main

// import (
// 	config "JobHuntz/app/configs"
// 	"JobHuntz/app/database"
// 	router "JobHuntz/app/routers"

// 	"github.com/labstack/echo/v4"
// 	"github.com/labstack/echo/v4/middleware"
// )

// func main() {

// 	// logging := helpers.NewLogger()
// 	cfg := config.InitConfig()
// 	dbMysql := database.InitDBMysql(cfg)

// 	//call migration
// 	database.InitialMigration(dbMysql)

// 	//create a new echo instance
// 	e := echo.New()

// 	e.Use(middleware.CORS())
// 	//remove pre trailingslash
// 	e.Pre(middleware.RemoveTrailingSlash())

// 	//e.Use middleware logger
// 	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
// 		Format: "method=${method}, uri=${uri}, status=${status}\n",
// 	}))

// 	router.InitRouter(dbMysql, e)

// 	//start server and port
// 	e.Logger.Fatal(e.Start(":8070"))
// }

// // func customTLSConfig() (*tls.Config, error) {
// // 	caCert, err := ioutil.ReadFile("server-ca.pem")
// // 	if err != nil {
// // 		return nil, err
// // 	}

// // 	certPool := x509.NewCertPool()
// // 	certPool.AppendCertsFromPEM(caCert)

// // 	return &tls.Config{
// // 		RootCAs: certPool,
// // 	}, nil
// // }

import (
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/oauth2/v2"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString  = "pseudo-random"
)

func init() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/callback",
		ClientID:     "591397371645-u97ubl37pme4gol5ck79qgfih0401ohg.apps.googleusercontent.com",
		ClientSecret: "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",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	var html = `<html><body><a href="/login">Google Log In</a></body></html>`
	w.Write([]byte(html))
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	client := googleOauthConfig.Client(oauth2.NoContext, token)
	service, err := oauth2.New(client)
	if err != nil {
		http.Error(w, "Failed to create OAuth2 service", http.StatusInternalServerError)
		return
	}

	userInfo, err := service.Userinfo.Get().Do()
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// You can use userInfo.Email or userInfo.Name here as per your requirement
	w.Write([]byte("Hello, " + userInfo.Email))
}

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleGoogleLogin)
	http.HandleFunc("/callback", handleGoogleCallback)
	http.ListenAndServe(":8080", nil)
}
