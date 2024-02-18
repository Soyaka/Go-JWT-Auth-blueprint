package controllers

import (
	"main/models"
	"main/utils"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("#@dsSDfs6aesf/*ses/s-19j82")

func Login(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var existingUser models.User
	models.DB.Where("email = ?", user.Email).First(&existingUser)
	if existingUser.ID == 0 {
		c.JSON(400, gin.H{"error": "user not-found"})
		return
	}
	errHash := utils.CompareHashPwd(user.Password, existingUser.Password)
	if !errHash {
		c.JSON(400, gin.H{"error": "invalid password"})
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &models.Claims{
		Role: existingUser.Role,
		StandardClaims: jwt.StandardClaims{
			Subject:   existingUser.Email,
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(500, gin.H{"error": "could not generate token"})
	}

	c.SetCookie("token", tokenString, int(expirationTime.Unix()), "/", "localhost", false, true)
	c.JSON(200, gin.H{"success": "log-in successfully"})

}

func Signup(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {

		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var existingUser models.User

	models.DB.Where("email=?", user.Email).First((&existingUser))
	if existingUser.ID != 0 {
		c.JSON(400, gin.H{"error": "user already exists"})
	}
	var errHash error
	user.Password, errHash = utils.GenerateHashPwd(user.Password)
	if errHash != nil {
		c.JSON(500, gin.H{"error": "could Not generate a password hash"})
		return
	}

	models.DB.Create(&user)
	c.JSON(201, gin.H{"message": "user created successfuly"})

}

func Home(c *gin.Context) {
	cookie, err := c.Cookie("token")

	if err != nil {
		c.JSON(401, gin.H{"message": "unathorized"})
		return

	}

	claims, err := utils.ParseToken(cookie)

	if err != nil {
		c.JSON(401, gin.H{"message": " Unauthorized"})
		return
	}
	if claims.Role != "user" && claims.Role != "admin" {
		c.JSON(401, gin.H{"message": "unauthorized"})
		return
	}
	c.JSON(200, gin.H{"suucces": " home page ", "role": claims.Role})

}

func Premium(c *gin.Context) {
	cookie, err := c.Cookie("token")
	if err != nil {

		c.JSON(401, gin.H{"message": " unAuthorized access"})
		return
	}

	claims, err := utils.ParseToken(cookie)
	if err != nil {
		c.JSON(402, gin.H{"error": "anAuthorized"})
	}
	if claims.Role != "admin" {
		c.JSON(401, gin.H{"error": "can't access the premuim sector"})
		return
	}

	c.JSON(200, gin.H{"success": " premuim page ", "role": "admin"})
}

func Logout(c *gin.Context) {
	c.SetCookie("token", "", -1, "/", "localhost", false, true)
	c.JSON(200, gin.H{"message ": "logut success"})
}
