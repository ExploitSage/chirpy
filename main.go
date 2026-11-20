package main

import (
    "os"
    "fmt"
    "time"
    "slices"
    "strings"
    "context"
    "net/http"
    "sync/atomic"
    "database/sql"
    "encoding/json"

	"github.com/google/uuid"
    "github.com/joho/godotenv"

    "github.com/exploitsage/chirpy/internal/auth"
    "github.com/exploitsage/chirpy/internal/database"
)

import _ "github.com/lib/pq"

type apiConfig struct {
    fileserverHits atomic.Int32
    queries        *database.Queries
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
    Token        string    `json:"token"`
    RefreshToken string    `json:"refresh_token"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
    UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cfg.fileserverHits.Add(1)
        next.ServeHTTP(w, r)
    })
}

func respondWithJSON(res http.ResponseWriter, code int, payload interface{}) {
    data, err := json.Marshal(payload)
    if err != nil {
        respondWithError(res, 500, "Failed to Compile JSON Response")
        return
    }

    res.Header().Add("Content-Type", "application/json")
    res.WriteHeader(code)
    res.Write(data)
}

func respondWithError(res http.ResponseWriter, code int, msg string) {
    type errors struct {
        Error string `json:"error"`
    }

    errorBody := errors{
        Error: msg,
    }

    respondWithJSON(res, code, errorBody)
}

func cleanString(msg string) string {
    swears:= []string{"kerfuffle", "sharbert", "fornax"}
    
    words := strings.Split(msg, " ")
    for idx, word := range words {
        if slices.Contains(swears, strings.ToLower(word)) {
            words[idx] = "****"
        }
    }

    return strings.Join(words, " ")
}

func main() {
    godotenv.Load()
    dbURL := os.Getenv("DB_URL")
    platform := os.Getenv("PLATFORM")
    tokenSecret := os.Getenv("JWTSECRET")

    db, _ := sql.Open("postgres", dbURL)
    dbQueries := database.New(db)

    apiCfg := apiConfig{queries: dbQueries}
    serveMux := http.NewServeMux()

    serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./")))))
    
    serveMux.HandleFunc("GET /api/healthz", func(res http.ResponseWriter, req *http.Request) {
        res.Header().Add("Content-Type", "text/plain; charset=utf-8")
        res.WriteHeader(200)
    })

    serveMux.HandleFunc("POST /api/login", func(res http.ResponseWriter, req *http.Request) {
        type reqBody struct {
            Email            string `json:"email"`
            Password         string `json:"password"`
        }

        decoder := json.NewDecoder(req.Body)
        loginParams := reqBody{}
        err := decoder.Decode(&loginParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Parse JSON Body")
            return
        }

        dbUser, err := dbQueries.ReadUserByEmail(context.Background(), loginParams.Email)
        if err != nil {
            respondWithError(res, 401, "Incorrect email or password")
            return
        }

        authenticated, err := auth.CheckPasswordHash(loginParams.Password, dbUser.HashedPassword)
        if err != nil || authenticated == false {
            respondWithError(res, 401, "Incorrect email or password")
            return
        }

        accessToken := auth.MakeRefreshToken()
        createRefreshTokenParams := database.CreateRefreshTokenParams{
            Token: accessToken,
            UserID: dbUser.ID,
        }

        dbAccessToken, err := dbQueries.CreateRefreshToken(context.Background(), createRefreshTokenParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Create Refresh Token")
            return
        }
        
        tokenDuration := time.Duration(1) * time.Hour
        token, err := auth.MakeJWT(dbUser.ID, tokenSecret, tokenDuration)
        if err != nil {
            respondWithError(res, 500, "Failed to Generate Bearer Token")
            return
        }

        user := User{
            ID: dbUser.ID,
            CreatedAt: dbUser.CreatedAt,
            UpdatedAt: dbUser.UpdatedAt,
            Email: dbUser.Email,
            Token: token,
            RefreshToken: dbAccessToken.Token,
        }

        respondWithJSON(res, 200, user)
    })

    serveMux.HandleFunc("POST /api/refresh", func(res http.ResponseWriter, req *http.Request) {
        type resBody struct {
            Token            string `json:"token"`
        }

        refreshToken, err := auth.GetBearerToken(req.Header)
        if err != nil {
            respondWithError(res, 500, err.Error())
            return
        }

        dbRefreshToken, err := dbQueries.ReadRefreshTokenByToken(context.Background(), refreshToken)
        if err != nil || dbRefreshToken.RevokedAt.Valid || dbRefreshToken.ExpiresAt.Before(time.Now()) {
            respondWithError(res, 401, "Unauthorized")
            return
        }

        tokenDuration := time.Duration(1) * time.Hour
        token, err := auth.MakeJWT(dbRefreshToken.UserID, tokenSecret, tokenDuration)
        if err != nil {
            respondWithError(res, 500, "Failed to Generate Bearer Token")
            return
        }

        newToken := resBody{
            Token: token,
        }

        respondWithJSON(res, 200, newToken)
    })

    serveMux.HandleFunc("POST /api/revoke", func(res http.ResponseWriter, req *http.Request) {
        refreshToken, err := auth.GetBearerToken(req.Header)
        if err != nil {
            respondWithError(res, 500, err.Error())
            return
        }

        _, err = dbQueries.UpdateRevokeRefreshToken(context.Background(), refreshToken)
        if err != nil {
            respondWithError(res, 500, err.Error())
            return
        }

        res.WriteHeader(204)
    })

    serveMux.HandleFunc("POST /api/users", func(res http.ResponseWriter, req *http.Request) {
        type reqBody struct {
            Email string `json:"email"`
            Password string `json:"password"`
        }

        decoder := json.NewDecoder(req.Body)
        userParams := reqBody{}
        err := decoder.Decode(&userParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Parse JSON Body")
            return
        }

        hashedPassword, err := auth.HashPassword(userParams.Password)
        if err != nil {
            respondWithError(res, 500, "Failed to Hash Provided Password")
            return
        }
        createUserParams := database.CreateUserParams{
            Email: userParams.Email,
            HashedPassword: hashedPassword,
        }

        dbUser, err := dbQueries.CreateUser(context.Background(), createUserParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Create User")
            return
        }

        newUser := User{
            ID: dbUser.ID,
            CreatedAt: dbUser.CreatedAt,
            UpdatedAt: dbUser.UpdatedAt,
            Email: dbUser.Email,
        }

        respondWithJSON(res, 201, newUser)
    })

    serveMux.HandleFunc("PUT /api/users", func(res http.ResponseWriter, req *http.Request) {
        type reqBody struct {
            Email string `json:"email"`
            Password string `json:"password"`
        }

        decoder := json.NewDecoder(req.Body)
        userParams := reqBody{}
        err := decoder.Decode(&userParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Parse JSON Body")
            return
        }

        token, err := auth.GetBearerToken(req.Header)
        if err != nil {
            respondWithError(res, 401, err.Error())
            return
        }

        userID, err := auth.ValidateJWT(token, tokenSecret)
        if err != nil {
            respondWithError(res, 401, err.Error())
            return
        }

        hashedPassword, err := auth.HashPassword(userParams.Password)
        if err != nil {
            respondWithError(res, 500, "Failed to Hash Provided Password")
            return
        }
        updateUserParams := database.UpdateUserParams{
            ID: userID,
            Email: userParams.Email,
            HashedPassword: hashedPassword,
        }

        dbUser, err := dbQueries.UpdateUser(context.Background(), updateUserParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Update User")
            return
        }

        updatedUser := User{
            ID: dbUser.ID,
            CreatedAt: dbUser.CreatedAt,
            UpdatedAt: dbUser.UpdatedAt,
            Email: dbUser.Email,
        }

        respondWithJSON(res, 200, updatedUser)
    })

    serveMux.HandleFunc("POST /api/chirps", func(res http.ResponseWriter, req *http.Request) {
        type reqBody struct {
            Body   string    `json:"body"`
        }

        decoder := json.NewDecoder(req.Body)
        chirpParams := reqBody{}
        err := decoder.Decode(&chirpParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Parse JSON Body")
            return
        }

        token, err := auth.GetBearerToken(req.Header)
        if err != nil {
            respondWithError(res, 500, err.Error())
            return
        }

        userID, err := auth.ValidateJWT(token, tokenSecret)
        if err != nil {
            respondWithError(res, 401, err.Error())
            return
        }

        if len(chirpParams.Body) > 140 {
            respondWithError(res, 400, "Chirp is too long")
            return
        }

        createChirpParams := database.CreateChirpParams{
            Body: cleanString(chirpParams.Body),
            UserID: userID,

        }

        dbChirp, err := dbQueries.CreateChirp(context.Background(), createChirpParams)
        if err != nil {
            respondWithError(res, 500, "Failed to Create Chirp")
            return
        }

        newChirp := Chirp{
            ID: dbChirp.ID,
            CreatedAt: dbChirp.CreatedAt,
            UpdatedAt: dbChirp.UpdatedAt,
            Body: dbChirp.Body,
            UserID: dbChirp.UserID,
        }

        respondWithJSON(res, 201, newChirp)
    })

    serveMux.HandleFunc("GET /api/chirps", func(res http.ResponseWriter, req *http.Request) {
        dbChirps, err := dbQueries.ReadChirps(context.Background())
        if err != nil {
            respondWithError(res, 500, "Failed to Read Chirps")
            return
        }

        chirps := []Chirp{}
        for _, dbChirp := range dbChirps {
            chirps = append(chirps, Chirp{
                ID: dbChirp.ID,
                CreatedAt: dbChirp.CreatedAt,
                UpdatedAt: dbChirp.UpdatedAt,
                Body: dbChirp.Body,
                UserID: dbChirp.UserID,
            })
        }

        respondWithJSON(res, 200, chirps)
    })

    serveMux.HandleFunc("GET /api/chirps/{chirpID}", func(res http.ResponseWriter, req *http.Request) {
        chirpID, err := uuid.Parse(req.PathValue("chirpID"))
        if err != nil {
            respondWithError(res, 500, "Failed to Parse Chirp ID")
            return
        }

        dbChirp, err := dbQueries.ReadChirp(context.Background(), chirpID)
        if err != nil {
            respondWithError(res, 404, "Failed to Find Chirp")
            return
        }

        chirp := Chirp{
            ID: dbChirp.ID,
            CreatedAt: dbChirp.CreatedAt,
            UpdatedAt: dbChirp.UpdatedAt,
            Body: dbChirp.Body,
            UserID: dbChirp.UserID,
        }

        respondWithJSON(res, 200, chirp)
    })

    serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", func(res http.ResponseWriter, req *http.Request) {
        chirpID, err := uuid.Parse(req.PathValue("chirpID"))
        if err != nil {
            respondWithError(res, 500, "Failed to Parse Chirp ID")
            return
        }

        dbChirp, err := dbQueries.ReadChirp(context.Background(), chirpID)
        if err != nil {
            respondWithError(res, 404, "Failed to Find Chirp")
            return
        }

        token, err := auth.GetBearerToken(req.Header)
        if err != nil {
            respondWithError(res, 401, err.Error())
            return
        }

        userID, err := auth.ValidateJWT(token, tokenSecret)
        if err != nil {
            respondWithError(res, 401, err.Error())
            return
        }

        if userID != dbChirp.UserID {
            respondWithError(res, 403, "You are not the Chirp's Author")
            return
        }

        err = dbQueries.DeleteChirp(context.Background(), dbChirp.ID)
        if err != nil {
            respondWithError(res, 500, "Failed to Delete Chirp")
            return
        }

        res.WriteHeader(204)
    })
    
    serveMux.HandleFunc("GET /admin/metrics", func(res http.ResponseWriter, req *http.Request) {
        res.Header().Add("Content-Type", "text/html; charset=utf-8")
        res.WriteHeader(200)
	    res.Write([]byte(fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
        `, apiCfg.fileserverHits.Load())))
    })
    
    serveMux.HandleFunc("POST /admin/reset", func(res http.ResponseWriter, req *http.Request) {
        if(platform != "dev") {
            respondWithError(res, 403, "Unavailable outside dev environment")
            return
        }
        apiCfg.fileserverHits.Store(0)
        _ = dbQueries.DeleteUsers(context.Background())
        res.Header().Add("Content-Type", "text/plain; charset=utf-8")
        res.WriteHeader(200)
    })
    
    server := http.Server{
        Addr: ":8080",
        Handler: serveMux,
    }
    server.ListenAndServe()
}
