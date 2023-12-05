package openidauthrol

import (
	"context"
	"net/http"
	"os"
	"fmt"
	"regexp"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"math/big"
	"crypto/rsa"
    "encoding/base64"
	"sync"
)

// Config the plugin configuration.
type Config struct {
	Keycloak string   `json:"headerName,omitempty"`
	Realms         string   `json:"realms,omitempty"`
}


// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{ 
	}
}


type Response struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

// Hols the necesaro components of a Traefic plugin
type OpenidAuthRol struct {
	next http.Handler
	name string
	publicKeyCache map[string]*rsa.PublicKey
    cacheMutex     *sync.RWMutex
	keycloak string 
	realms   string    
}

type JWK struct {
    Kid string `json:"kid"`
    Kty string `json:"kty"`
    Alg string `json:"alg"`
    Use string `json:"use"`
    N   string `json:"n"`
    E   string `json:"e"`
    X5c []string `json:"x5c"`
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Keycloak)==0 || len(config.Realms) == 0{
		return nil , fmt.Errorf("Missing realms or keycloak ")
	}

	return &OpenidAuthRol{
		next:     next,
		name:     name,
		publicKeyCache: make(map[string]*rsa.PublicKey),
        cacheMutex:     &sync.RWMutex{},
		keycloak : config.Keycloak,
		realms: config.Realms,
	}, nil
}

func extractBearerToken(authHeader string) (string, error) {
    parts := strings.Split(authHeader, " ")
    if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
        return "", fmt.Errorf("formato de encabezado de autorización inválido")
    }
    return parts[1], nil
}


func ( u *OpenidAuthRol) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	//os.Stderr.WriteString("Log: Hola mundo desde log")
	//req.Header.Set("Authentication" , "Bearear hola mundo")
	//u.next.ServeHTTP(rw, req)

	AuthHeader := req.Header.Get("Authorization")
	tokenString , err := extractBearerToken(AuthHeader)
	
	header, err := getJWTHeader(tokenString)
    if err != nil {
        handleErrorResponse(rw, "Error al obtener el encabezado del token", http.StatusUnauthorized)
        return
    }

	kid, ok := header["kid"].(string)
    if !ok {
        handleErrorResponse(rw, "Token JWT sin 'kid' en el encabezado", http.StatusUnauthorized)
        return
    }
	// Print  Kid
	//os.Stderr.WriteString("Kid: " + kid + " ")
	keycloakCertsURL := u.keycloak+"/realms/"+u.realms+"/protocol/openid-connect/certs"
	
	publicKey, err := u.getRSAPublicKey(kid, keycloakCertsURL)
    if err != nil {
        handleErrorResponse(rw, "Error al obtener la llave pública", http.StatusInternalServerError)
        return
    }

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return publicKey, nil
    })

	if err != nil {
		handleErrorResponse(rw, "Invalid Token", http.StatusInternalServerError)
        return
    }

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        u.next.ServeHTTP(rw, req)
    } else {
		handleErrorResponse(rw, "Error token", http.StatusInternalServerError)
    }
}

func decodeBase64URL(s string) (*big.Int, error) {
    b, err := base64.RawURLEncoding.DecodeString(s)
    if err != nil {
        return nil, err
    }
    return new(big.Int).SetBytes(b), nil
}

func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
    n, err := decodeBase64URL(jwk.N)
    if err != nil {
        return nil, err
    }
    e, err := decodeBase64URL(jwk.E)
    if err != nil {
        return nil, err
    }
    return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func getJWTHeader(tokenString string) (map[string]interface{}, error) {
    parts := strings.Split(tokenString, ".")
    if len(parts) != 3 {
        return nil, fmt.Errorf("el token no tiene el formato correcto")
    }

    headerPart := parts[0]
    headerBytes, err := base64.RawURLEncoding.DecodeString(headerPart)
    if err != nil {
        return nil, fmt.Errorf("error al decodificar el encabezado del token: %v", err)
    }

    var header map[string]interface{}
    err = json.Unmarshal(headerBytes, &header)
    if err != nil {
        return nil, fmt.Errorf("error al deserializar el encabezado del token: %v", err)
    }

    return header, nil
}

func handleErrorResponse(rw http.ResponseWriter, message string, statusCode int) {
    response := Response{
        Message:    message,
        StatusCode: statusCode,
    }
    responseJSON, _ := json.Marshal(response)
    rw.Header().Set("Content-Type", "application/json; charset=utf-8")
    rw.WriteHeader(statusCode)
    rw.Write(responseJSON)
}

func  (u *OpenidAuthRol) getRSAPublicKey(kid string, keycloakCertsURL string) (*rsa.PublicKey, error) {
    u.cacheMutex.RLock()
    if key, found := u.publicKeyCache[kid]; found {
        u.cacheMutex.RUnlock()
        return key, nil
    }
    u.cacheMutex.RUnlock()

	resp, err := http.Get(keycloakCertsURL)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

	var jwks JWKS
    if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
        panic(err)
    }


    for _, jwk := range jwks.Keys {
        if jwk.Kid == kid {
            publicKey, err := jwkToRSAPublicKey(&jwk)
            if err != nil {
                return nil, err
            }
            u.cacheMutex.Lock()
            u.publicKeyCache[kid] = publicKey
            u.cacheMutex.Unlock()
            return publicKey, nil
        }
    }
    return nil, fmt.Errorf("no se encontró la llave pública correspondiente")
}


