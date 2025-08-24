package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	log          = logrus.New()
	jwtSecret    string
)

type AuthRequest struct {
	Code     string `json:"code"`
	Provider string `json:"provider"` // google, facebook, linkedin
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Picture   string `json:"picture"`
	jwt.RegisteredClaims
}

func main() {
	// Загрузка .env
	if err := godotenv.Load(); err != nil {
		log.Warn("No .env file found")
	}

	// Инициализация логирования
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)

	// Конфигурация
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	realm := os.Getenv("KEYCLOAK_REALM")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	redirectURI := os.Getenv("REDIRECT_URI")
	jwtSecret = os.Getenv("JWT_SECRET")
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8081"
	}

	// Инициализация OIDC provider
	provider, err := oidc.NewProvider(context.Background(), fmt.Sprintf("%s/realms/%s", keycloakURL, realm))
	if err != nil {
		log.Fatal("Failed to create OIDC provider: ", err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// Gin сервер
	r := gin.Default()

	// CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"}, // Добавьте ваш frontend origin
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.POST("/auth/social/login", socialLogin)
	r.GET("/auth/user-info", jwtMiddleware, userInfo)
	r.POST("/auth/refresh", refreshTokenHandler)

	log.Info("Starting server on port " + port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("Failed to start server: ", err)
	}
}

// Обмен кода на токены
func socialLogin(c *gin.Context) {
	var req AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithFields(logrus.Fields{"ip": c.ClientIP(), "error": err}).Error("Invalid request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	ip := c.ClientIP()
	log.WithFields(logrus.Fields{"ip": ip, "provider": req.Provider}).Info("Login attempt")

	token, err := oauth2Config.Exchange(context.Background(), req.Code)
	if err != nil {
		log.WithFields(logrus.Fields{"ip": ip, "provider": req.Provider, "error": err}).Error("Token exchange failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token exchange failed"})
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.WithFields(logrus.Fields{"ip": ip}).Error("No id_token in response")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No id_token"})
		return
	}

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		log.WithFields(logrus.Fields{"ip": ip, "error": err}).Error("ID token verification failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ID token verification failed"})
		return
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		log.WithFields(logrus.Fields{"ip": ip, "error": err}).Error("Claims extraction failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Claims extraction failed"})
		return
	}

	// Генерация кастомного JWT (опционально, с exp 1h)
	jwtClaims := jwt.MapClaims{
		"email":      claims.Email,
		"first_name": claims.FirstName,
		"last_name":  claims.LastName,
		"picture":    claims.Picture,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Unix(),
		"sub":        idToken.Subject,
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signedJWT, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		log.WithFields(logrus.Fields{"ip": ip, "error": err}).Error("JWT signing failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT signing failed"})
		return
	}

	log.WithFields(logrus.Fields{"ip": ip, "provider": req.Provider, "user": claims.Email}).Info("Login successful")

	c.JSON(http.StatusOK, gin.H{
		"jwt":           signedJWT,
		"refresh_token": token.RefreshToken,
	})
}

// Middleware для валидации JWT
func jwtMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
		c.Abort()
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		log.WithFields(logrus.Fields{"ip": c.ClientIP(), "error": err}).Warn("Invalid JWT")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid JWT"})
		c.Abort()
		return
	}

	c.Next()
}

// Получение user info из JWT
func userInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	token, _ := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	claims := token.Claims.(*jwt.MapClaims)
	c.JSON(http.StatusOK, gin.H{
		"email":      (*claims)["email"],
		"first_name": (*claims)["first_name"],
		"last_name":  (*claims)["last_name"],
		"picture":    (*claims)["picture"],
	})
}

// Обновление токена
func refreshTokenHandler(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	source := oauth2.StaticTokenSource(&oauth2.Token{RefreshToken: req.RefreshToken})
	newToken, err := source.Token()
	if err != nil {
		log.WithFields(logrus.Fields{"ip": c.ClientIP(), "error": err}).Error("Refresh failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh failed"})
		return
	}

	// Повторно генерируем JWT из новых claims (аналогично login)
	rawIDToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No id_token"})
		return
	}

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "ID token verification failed"})
		return
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Claims extraction failed"})
		return
	}

	jwtClaims := jwt.MapClaims{
		"email":      claims.Email,
		"first_name": claims.FirstName,
		"last_name":  claims.LastName,
		"picture":    claims.Picture,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"iat":        time.Now().Unix(),
		"sub":        idToken.Subject,
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signedJWT, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "JWT signing failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"jwt":           signedJWT,
		"refresh_token": newToken.RefreshToken,
	})
}
