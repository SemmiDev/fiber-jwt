package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	_ "github.com/joho/godotenv/autoload" // load .env file automatically
	"github.com/rs/zerolog"
	"github.com/twinj/uuid"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type User struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var user = User{
	ID:       1,
	Email:    "sammidev@gmail.com",
	Password: "sammidev",
}

type Todo struct {
	UserID int64  `json:"user_id"`
	Title  string `json:"title"`
}

// logging
var logger = zerolog.New(zerolog.ConsoleWriter{
	Out:        os.Stdout,
	NoColor:    false,
	TimeFormat: time.RFC3339,
}).With().Timestamp().Logger().Level(zerolog.GlobalLevel())

func Success(c *fiber.Ctx, code int, payload interface{}) error {
	c.Set("Content-Type", "application/json")
	c.Status(code)
	return c.JSON(payload)
}

func Error(c *fiber.Ctx, code int, err error) error {
	c.Set("Content-Type", "application/json")
	c.Status(code)
	return c.JSON(struct {
		Message string `json:"message"`
	}{Message: err.Error()})
}

func init() {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	client = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port
	})
	_, err := client.Ping(context.Background()).Result()
	if err != nil {
		panic(err)
	}
}

var client *redis.Client

func FiberMiddleware(a *fiber.App) {
	a.Use(
		// Add CORS to each route.
		cors.New(),
		// Add simple logger.
		fiberlogger.New(),
		// add recoverer for panic
		recover.New(),
	)
}

func main() {
	readTimeoutSecondsCount, _ := strconv.Atoi(os.Getenv("SERVER_READ_TIMEOUT"))
	app := fiber.New(fiber.Config{
		ReadTimeout: time.Second * time.Duration(readTimeoutSecondsCount),
	})

	FiberMiddleware(app)
	route := app.Group("api/v1")

	route.Post("/login", Login)
	route.Post("/todo", CreateTodo)
	route.Post("/logout", Logout)
	route.Post("/refresh", Refresh)

	logger.Log().Err(app.Listen(os.Getenv("SERVER_URL")))
}

func Login(c *fiber.Ctx) error {
	var u User
	if err := c.BodyParser(&u); err != nil {
		return Error(c, fiber.StatusUnauthorized, errors.New("invalid json provided"))
	}

	//compare the user from the request, with the one we defined:
	if user.Email != u.Email || user.Password != u.Password {
		return Error(c, fiber.StatusUnauthorized, errors.New("please provide valid login details"))
	}

	ts, err := CreateToken(user.ID)
	if err != nil {
		return Error(c, fiber.StatusUnprocessableEntity, err)
	}

	saveErr := CreateAuth(c, user.ID, ts)
	if saveErr != nil {
		return Error(c, http.StatusUnprocessableEntity, saveErr)
	}

	return Success(c, fiber.StatusOK, fiber.Map{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	})
}

func CreateTodo(c *fiber.Ctx) error {
	var td Todo
	if err := c.BodyParser(&td); err != nil {
		return Error(c, fiber.StatusUnprocessableEntity, errors.New("invalid json"))

	}
	//Extract the access token metadata
	metadata, err := ExtractTokenMetadata(c)
	if err != nil {
		return Error(c, fiber.StatusUnauthorized, errors.New("unauthorized"))
	}
	userid, err := FetchAuth(c, metadata)
	if err != nil {
		return Error(c, fiber.StatusUnauthorized, err)

	}

	td.UserID = userid
	//you can proceed to save the Todo to a database

	return Success(c, fiber.StatusCreated, td)
}

func Logout(c *fiber.Ctx) error {
	metadata, err := ExtractTokenMetadata(c)
	if err != nil {
		return Error(c, fiber.StatusUnauthorized, errors.New("unauthorized"))
	}

	delErr := DeleteTokens(c, metadata)
	if delErr != nil {
		return Error(c, fiber.StatusUnauthorized, delErr)
	}
	return Success(c, fiber.StatusOK, "successfully logged out")
}

func Refresh(c *fiber.Ctx) error {
	mapToken := map[string]string{}
	if err := c.BodyParser(&mapToken); err != nil {
		return Error(c, fiber.StatusUnprocessableEntity, err)

	}
	refreshToken := mapToken["refresh_token"]

	//verify the token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})

	//if there is an error, the token must have expired
	if err != nil {
		fmt.Println("the error: ", err)
		return Error(c, fiber.StatusUnauthorized, errors.New("refresh token expired"))
	}

	//is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return Error(c, fiber.StatusUnauthorized, err)
	}

	//Since token is valid, get the uuid:
	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			return Error(c, fiber.StatusUnprocessableEntity, err)
		}
		userId, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return Error(c, fiber.StatusUnprocessableEntity, errors.New("error occurred"))
		}

		deleted, delErr := DeleteAuth(c, refreshUuid)
		if delErr != nil || deleted == 0 { //if any goes wrong
			//Delete the previous Refresh Token
			return Error(c, fiber.StatusUnauthorized, errors.New("unauthorized"))
		}

		//Create new pairs of refresh and access tokens
		ts, createErr := CreateToken(userId)
		if createErr != nil {
			return Error(c, fiber.StatusForbidden, createErr)
		}

		saveErr := CreateAuth(c, userId, ts)
		if saveErr != nil {
			//save the tokens metadata to redis
			return Error(c, fiber.StatusForbidden, saveErr)
		}

		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		return Success(c, fiber.StatusCreated, tokens)
	} else {
		return Error(c, fiber.StatusUnauthorized, errors.New("refresh expired"))
	}
}

type AccessDetails struct {
	AccessUuid string
	UserId     int64
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

func CreateToken(userid int64) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AtExpires = time.Now().Add(time.Minute * 15).Unix()
	td.AccessUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = td.AccessUuid + "++" + strconv.Itoa(int(userid))

	var err error
	//Creating Access Token
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["access_uuid"] = td.AccessUuid
	atClaims["user_id"] = userid
	atClaims["exp"] = td.AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}

	//Creating Refresh Token
	rtClaims := jwt.MapClaims{}
	rtClaims["refresh_uuid"] = td.RefreshUuid
	rtClaims["user_id"] = userid
	rtClaims["exp"] = td.RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	return td, nil
}

func CreateAuth(c *fiber.Ctx, userid int64, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0) //converting Unix to UTC(to Time object)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	errAccess := client.Set(c.Context(), td.AccessUuid, strconv.Itoa(int(userid)), at.Sub(now)).Err()
	if errAccess != nil {
		return errAccess
	}
	errRefresh := client.Set(c.Context(), td.RefreshUuid, strconv.Itoa(int(userid)), rt.Sub(now)).Err()
	if errRefresh != nil {
		return errRefresh
	}
	return nil
}

func ExtractToken(c *fiber.Ctx) string {
	bearToken := c.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(c *fiber.Ctx) (*jwt.Token, error) {
	tokenString := ExtractToken(c)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func TokenValid(c *fiber.Ctx) error {
	token, err := VerifyToken(c)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok || !token.Valid {
		return err
	}
	return nil
}

func ExtractTokenMetadata(c *fiber.Ctx) (*AccessDetails, error) {
	token, err := VerifyToken(c)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		if !ok {
			return nil, err
		}
		userId, err := strconv.ParseInt(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			return nil, err
		}
		return &AccessDetails{
			AccessUuid: accessUuid,
			UserId:     userId,
		}, nil
	}
	return nil, err
}

func FetchAuth(c *fiber.Ctx, authD *AccessDetails) (int64, error) {
	userid, err := client.Get(c.Context(), authD.AccessUuid).Result()
	if err != nil {
		return 0, err
	}
	userID, _ := strconv.ParseInt(userid, 10, 64)
	if authD.UserId != userID {
		return 0, errors.New("unauthorized")
	}
	return userID, nil
}

func DeleteAuth(c *fiber.Ctx, givenUuid string) (int64, error) {
	deleted, err := client.Del(c.Context(), givenUuid).Result()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func DeleteTokens(c *fiber.Ctx, authD *AccessDetails) error {
	//get the refresh uuid
	refreshUuid := fmt.Sprintf("%s++%d", authD.AccessUuid, authD.UserId)
	//delete access token
	deletedAt, err := client.Del(c.Context(), authD.AccessUuid).Result()
	if err != nil {
		return err
	}
	//delete refresh token
	deletedRt, err := client.Del(c.Context(), refreshUuid).Result()
	if err != nil {
		return err
	}
	//When the record is deleted, the return value is 1
	if deletedAt != 1 || deletedRt != 1 {
		return errors.New("something went wrong")
	}
	return nil
}
