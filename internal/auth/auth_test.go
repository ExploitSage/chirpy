package auth

import (
	"testing"
    "time"
    "regexp"

	"github.com/google/uuid"
)


func TestPasswordSuccess(t *testing.T) {
    password := "password1234"

    hash, err := HashPassword(password)
    if err != nil {
        t.Errorf(`HashPassword("%v") = %q, %v, want <hash>, nil`, password, hash, err)
    }

	valid, err := CheckPasswordHash(password, hash)
	if !valid || err != nil {
        t.Errorf(`CheckPasswordHash("%v", "%v") = %v, %v, want match for %v, nil`, password, hash, valid, err, true)
    }
}

func TestPasswordFail(t *testing.T) {
    password := "password1234"
	password2 := "P@s$w0rd12E4"
	
    hash, err := HashPassword(password)
    if err != nil {
        t.Errorf(`HashPassword("%v") = <hash>, %v; want <hash>, nil`, password, err)
    }

	valid, err := CheckPasswordHash(password2, hash)
	if valid || err != nil {
        t.Errorf(`CheckPasswordHash("%v", "<hash>") = %v, %v; want %v, nil`, password2, valid, err, false)
    }
}


func TestTokenSuccess(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "TestSecret"
	expiresIn := time.Duration(1)*time.Minute

    token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Errorf(`MakeJWT(%v, "%v", %v) = %v, %v; want <token>, nil`, userID, tokenSecret, expiresIn, token, err)
	}

	tokenID, err := ValidateJWT(token, tokenSecret)
	if tokenID != userID || err != nil {
		t.Errorf(`ValidateJWT(%v, "%v") = %v, %v; want %v, nil`, token, tokenSecret, tokenID, err, userID)
	}
}

func TestTokenExpired(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "TestSecret"
	expiresIn := time.Duration(0)*time.Minute
	want := regexp.MustCompile(`\b`+"token is expired"+`\b`)

    token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Errorf(`MakeJWT(%v, "%v", %v) = %v, %v; want <token>, nil`, userID, tokenSecret, expiresIn, token, err)
	}

	tokenID, err := ValidateJWT(token, tokenSecret)
	if !want.MatchString(err.Error()) || tokenID == userID || err == nil {
		t.Errorf(`ValidateJWT(%v, "%v") = %v, %v; want %v, %#q`, token, tokenSecret, tokenID, err, uuid.Nil, want)
	}
}

func TestTokenFail(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "TestSecret"
	tokenSecret2 := "WRONGSecret"
	expiresIn := time.Duration(1)*time.Minute
	want := regexp.MustCompile(`\b`+"signature is invalid"+`\b`)

    token, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil {
		t.Errorf(`MakeJWT(%v, "%v", %v) = %v, %v; want <token>, nil`, userID, tokenSecret, expiresIn, token, err)
	}

	tokenID, err := ValidateJWT(token, tokenSecret2)
	if tokenID == userID || err == nil {
		t.Errorf(`ValidateJWT(%v, "%v") = %v, %v; want %v, %#q`, token, tokenSecret2, tokenID, err, uuid.Nil, want)
	}
}

// TestHelloName calls greetings.Hello with a name, checking
// for a valid return value.
// func TestHelloName(t *testing.T) {
//     name := "Gladys"
//     want := regexp.MustCompile(`\b`+name+`\b`)
//     msg, err := Hello("Gladys")
//     if !want.MatchString(msg) || err != nil {
//         t.Errorf(`Hello("Gladys") = %q, %v, want match for %#q, nil`, msg, err, want)
//     }
// }

// TestHelloEmpty calls greetings.Hello with an empty string,
// checking for an error.
// func TestHelloEmpty(t *testing.T) {
//     msg, err := Hello("")
//     if msg != "" || err == nil {
//         t.Errorf(`Hello("") = %q, %v, want "", error`, msg, err)
//     }
// }
