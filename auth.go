package auth

import (
	"errors"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type auth struct {
	hash    string
	user    interface{}
	userID  int
	session sessions.Session
	pepper  string
}

type serchByCredentials func(string) (string, int, interface{})
type serchByID func(int) interface{}

var serch serchByCredentials
var serchID serchByID

// Auth struct
var _auth auth

var (
	// ErrInvalidPasswordRepeat for [to descibe]
	ErrInvalidPasswordRepeat = errors.New("Auth: invalid password repeat")
	// ErrInvalidLogin invalid login
	ErrInvalidLogin = errors.New("Auth: invalid login")
	// ErrInvalidPassword invalid password
	ErrInvalidPassword = errors.New("Auth: invalid password")
	// ErrNoUserLogedIn user dont loget in
	ErrNoUserLogedIn = errors.New("Auth: no user loged in")
)

// Midelware for authention
func Midelware(pepper string) gin.HandlerFunc {
	_auth.pepper = pepper
	return func(c *gin.Context) {
		_auth.user = nil
		_auth.userID = 0
		_auth.session = sessions.Default(c)
		userID := _auth.session.Get("auth_user_id")
		if userID != nil {
			id := userID.(int)
			if id > 0 {
				_auth.user = serchID(id)
				_auth.userID = id
			}
		}
	}
}

// Logout user
func Logout() {
	_auth.user = nil
	_auth.userID = 0
	_auth.session.Set("auth_user_id", 0)
	_auth.session.Save()
}

// Login authenticate user
func Login(login string, password string) error {
	hash, id, user := serch(login)
	if user == nil {
		return ErrInvalidLogin
	}
	err := comparePassword(hash, login, password)
	if err != nil {
		return ErrInvalidPassword
	}
	_auth.user = user
	_auth.userID = id
	_auth.session.Set("auth_user_id", _auth.userID)
	_auth.session.Save()
	return nil
}

// Serch set function for serching user by credentials
func Serch(fn serchByCredentials) {
	serch = fn
}

// SerchByID set function for serching user by ID
func SerchByID(fn serchByID) {
	serchID = fn
}

// CurrentUser return id and user object curently loged in
func CurrentUser() (int, interface{}, error) {
	if _auth.userID > 0 {
		return _auth.userID, _auth.user, nil
	}
	return 0, nil, ErrNoUserLogedIn
}

func pass(login string, password string) []byte {
	return []byte(login + password + _auth.pepper)
}

// Password generator
func Password(login string, password string) (string, error) {
	pass := pass(login, password)
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.DefaultCost)
	return string(hash), err
}

func comparePassword(hash string, login string, password string) error {
	pass := pass(login, password)
	return bcrypt.CompareHashAndPassword([]byte(hash), pass)
}

func validatePass(c *gin.Context, passName string, repeatName string) error {
	passName = c.PostForm(passName)
	repeatName = c.PostForm(repeatName)
	if passName == repeatName {
		return nil
	}
	return ErrInvalidPasswordRepeat
}

// GenPass generete password from post parameters
func GenPass(c *gin.Context, loginName, passName, repeatName string) (string, error) {
	err := validatePass(c, passName, repeatName)
	if err != nil {
		return c.PostForm(repeatName), err
	}
	return Password(c.PostForm(loginName), c.PostForm(passName))
}
