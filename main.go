package main

import (
    "os"
    "fmt"
    "strings"
    "slices"
    "encoding/json"
    "net/http"
    "sync/atomic"
    "database/sql"

    "github.com/joho/godotenv"

    "github.com/exploitsage/chirpy/internal/database"
)

import _ "github.com/lib/pq"

type apiConfig struct {
    fileserverHits atomic.Int32
    queries *database.Queries
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
    db, _ := sql.Open("postgres", dbURL)
    dbQueries := database.New(db)

    apiCfg := apiConfig{queries: dbQueries}
    serveMux := http.NewServeMux()

    serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("./")))))
    
    serveMux.HandleFunc("GET /api/healthz", func(res http.ResponseWriter, req *http.Request) {
        res.Header().Add("Content-Type", "text/plain; charset=utf-8")
        res.WriteHeader(200)
        res.Write([]byte("OK"))
    })

    serveMux.HandleFunc("POST /api/validate_chirp", func(res http.ResponseWriter, req *http.Request) {
        type chirps struct {
            Body string `json:"body"`
        }

        type chirpResponses struct {
            CleanedBody string `json:"cleaned_body"`
        }

        decoder := json.NewDecoder(req.Body)
        chirp := chirps{}
        err := decoder.Decode(&chirp)
        if err != nil {
            respondWithError(res, 500, "Failed to Parse JSON Body")
            return
        }
        
        if len(chirp.Body) > 140 {
            respondWithError(res, 400, "Chirp is too long")
            return
        }

        chirpResponse := chirpResponses{
            CleanedBody: cleanString(chirp.Body),
        }
        respondWithJSON(res, 200, chirpResponse)
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
        apiCfg.fileserverHits.Store(0)
        res.Header().Add("Content-Type", "text/plain; charset=utf-8")
        res.WriteHeader(200)
        res.Write([]byte("OK"))
    })
    
    server := http.Server{
        Addr: ":8080",
        Handler: serveMux,
    }
    server.ListenAndServe()
}
