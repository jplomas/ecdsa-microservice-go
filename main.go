package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"

	"github.com/ubiq/go-ubiq/crypto/secp256k1"
)

// IP addresses for logging
func getIP(r *http.Request) (string, error) {
	//Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	//Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip, nil
		}
	}

	//Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}
	return "", fmt.Errorf("No valid ip found")
}

// GeneratePrivateKey : ecdsa.PrivateKey
func GeneratePrivateKey() (*big.Int, error) {
	var privateKey *ecdsa.PrivateKey
	var privateKeyGenerationError error
	privateKey, privateKeyGenerationError = ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if privateKeyGenerationError != nil {
		return privateKey.D, privateKeyGenerationError
	}
	return privateKey.D, nil
}

// GeneratePublicKey : ecdsa.PublicKey
func GeneratePublicKey(privateKey *big.Int) ecdsa.PublicKey {
	var pri ecdsa.PrivateKey
	pri.D, _ = new(big.Int).SetString(fmt.Sprintf("%x", privateKey), 16)
	pri.PublicKey.Curve = secp256k1.S256()
	pri.PublicKey.X, pri.PublicKey.Y = pri.PublicKey.Curve.ScalarBaseMult(pri.D.Bytes())
	publicKey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     pri.PublicKey.X,
		Y:     pri.PublicKey.Y,
	}
	return publicKey
}

// Signature structure
type Signature struct {
	R *big.Int
	S *big.Int
}

// SignMessage : Sign a message
func SignMessage(message string, privateKey *big.Int) (Signature, error) {
	var result Signature
	msgHash := fmt.Sprintf(
		"%x",
		sha256.Sum256([]byte(message)),
	)
	privateKeyStruct, privateKeyGenerationError := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if privateKeyGenerationError != nil {
		return result, privateKeyGenerationError
	}
	privateKeyStruct.D = privateKey
	signatureR, signatureS, signatureGenerationError := ecdsa.Sign(rand.Reader, privateKeyStruct, []byte(msgHash))
	if signatureGenerationError != nil {
		return result, signatureGenerationError
	}
	result.R = signatureR
	result.S = signatureS
	return result, nil
}

// VerifyMessage : Verify a message
func VerifyMessage(message string, publicKey *ecdsa.PublicKey, signature Signature) (bool, error) {
	msgHash := fmt.Sprintf(
		"%x",
		sha256.Sum256([]byte(message)),
	)
	return ecdsa.Verify(publicKey, []byte(msgHash), signature.R, signature.S), nil
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	ip, err := getIP(r)
	if err != nil {
		log.Print("Serving /verify to ", ip)
	} else {
		log.Print("Serving /verify to ", r.RemoteAddr)
	}
	if r.Method != "POST" {
		http.Error(w, "Method not supported", http.StatusNotFound)
		log.Print("Error: POST not used")
		return
	}
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		log.Print("Error: Unable to parse form data")
		return
	}
	message := r.FormValue("Message")
	if message == "" {
		fmt.Fprintf(w, "%s", "Invalid message")
		log.Print("Error: No message sent")
		return
	}
	X := r.FormValue("X")
	if X == "" {
		fmt.Fprintf(w, "%s", "Invalid PK.X")
		log.Print("Error: No PK.X")
		return
	}
	Y := r.FormValue("Y")
	if Y == "" {
		fmt.Fprintf(w, "%s", "Invalid PK.Y")
		log.Print("Error: No PK.Y")
		return
	}
	R := r.FormValue("R")
	if R == "" {
		fmt.Fprintf(w, "%s", "Invalid Signature.R")
		log.Print("Error: No Signature.R")
		return
	}
	S := r.FormValue("S")
	if S == "" {
		fmt.Fprintf(w, "%s", "Invalid Signature.S")
		log.Print("Error: No Signature.S")
		return
	}
	var sigR, sigRError = new(big.Int).SetString(R, 0)
	if sigRError == false {
		fmt.Fprintf(w, "%s", "Invalid Signature.R")
		log.Print("Error: Invalid Signature.R")
		return
	}
	var sigS, sigSError = new(big.Int).SetString(S, 0)
	if sigSError == false {
		fmt.Fprintf(w, "%s", "Invalid Signature.S")
		log.Print("Error: Invalid Signature.S")
		return
	}
	var sigToVerify = Signature{sigR, sigS}
	var vp2, vp2err = new(big.Int).SetString(X, 0)
	if vp2err == false {
		fmt.Fprintf(w, "%s", "Invalid PK.X")
		log.Print("Error: Invalid PK.X")
		return
	}
	var vp3, vp3err = new(big.Int).SetString(Y, 0)
	if vp3err == false {
		fmt.Fprintf(w, "%s", "Invalid PK.Y")
		log.Print("Error: Invalid PK.Y")
		return
	}
	publicKey := ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     vp2,
		Y:     vp3,
	}

	var verify, _ = VerifyMessage(message, &publicKey, sigToVerify)

	fmt.Fprintf(w, "%s", "{\"message\":\"")
	fmt.Fprintf(w, "%s", message)
	fmt.Fprintf(w, "%s", "\",\"PK\":{\"X\":\"")
	fmt.Fprintf(w, "%s", vp2)
	fmt.Fprintf(w, "%s", "\",\"Y\":\"")
	fmt.Fprintf(w, "%s", vp3)
	fmt.Fprintf(w, "%s", "\"}")
	fmt.Fprintf(w, "%s", ",\"signature\":{\"R\":\"")
	fmt.Fprintf(w, "%s", sigR)
	fmt.Fprintf(w, "%s", "\",\"S\":\"")
	fmt.Fprintf(w, "%s", sigS)
	fmt.Fprintf(w, "%s", "\"},\"verified\":")
	fmt.Fprintf(w, "%t", verify)
	fmt.Fprintf(w, "%s", "}")
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	ip, err := getIP(r)
	if err != nil {
		log.Print("Serving /sign to ", ip)
	} else {
		log.Print("Serving /sign to ", r.RemoteAddr)
	}
	if r.Method != "POST" {
		http.Error(w, "Method not supported", http.StatusNotFound)
		log.Print("Error: POST not used")
		return
	}
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		log.Print("Error: Unable to parse form data")
		return
	}
	sk := r.FormValue("SK")
	if sk == "" {
		fmt.Fprintf(w, "%s", "Invalid SK")
		log.Print("Error: No SK sent")
		return
	}
	message := r.FormValue("Message")
	if message == "" {
		fmt.Fprintf(w, "%s", "Invalid message")
		log.Print("Error: No message sent")
		return
	}
	var secretKey, skError = new(big.Int).SetString(sk, 0)
	if skError == false {
		fmt.Fprintf(w, "%s", "Invalid SK")
		log.Print("Error: Invalid SK sent")
		return
	}
	var signed, _ = SignMessage(message, secretKey)
	fmt.Fprintf(w, "%s", "{\"message\":\"")
	fmt.Fprintf(w, "%s", message)
	fmt.Fprintf(w, "%s", "\",\"signed\":")
	fmt.Fprintf(w, "%s", "{\"R\":\"")
	fmt.Fprintf(w, "%s", signed.R)
	fmt.Fprintf(w, "%s", "\",\"S\":\"")
	fmt.Fprintf(w, "%s", signed.S)
	fmt.Fprintf(w, "%s", "\"}}")
}

func getPKHandler(w http.ResponseWriter, r *http.Request) {
	ip, err := getIP(r)
	if err != nil {
		log.Print("Serving /pk to ", ip)
	} else {
		log.Print("Serving /pk to ", r.RemoteAddr)
	}
	if r.Method != "POST" {
		http.Error(w, "Method not supported", http.StatusNotFound)
		log.Print("Error: POST not used")
		return
	}
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm() err: %v", err)
		log.Print("Error: Unable to parse form data")
		return
	}
	sk := r.FormValue("SK")
	if sk == "" {
		fmt.Fprintf(w, "%s", "Invalid SK")
		log.Print("Error: No SK sent")
		return
	}
	var secretKey, skError = new(big.Int).SetString(sk, 0)
	if skError == false {
		fmt.Fprintf(w, "%s", "Invalid SK")
		log.Print("Error: Invalid SK sent")
		return
	}
	var pk = GeneratePublicKey(secretKey)
	fmt.Fprintf(w, "%s", "{\"SK\":\"")
	fmt.Fprintf(w, "%s", sk)
	fmt.Fprintf(w, "%s", "\",\"PK\":{\"X\":\"")
	fmt.Fprintf(w, "%s", pk.X)
	fmt.Fprintf(w, "%s", "\",\"Y\":\"")
	fmt.Fprintf(w, "%s", pk.Y)
	fmt.Fprintf(w, "%s", "\"}}")
}

func newSKHandler(w http.ResponseWriter, r *http.Request) {
	ip, err := getIP(r)
	if err != nil {
		log.Print("Serving /sk to ", ip)
	} else {
		log.Print("Serving /sk to ", r.RemoteAddr)
	}
	if r.Method != "GET" {
		http.Error(w, "Method not supported", http.StatusNotFound)
		log.Print("Error: GET method not used")
		return
	}

	var sk, _ = GeneratePrivateKey()

	fmt.Fprintf(w, "%s", "{\"SK\":\"")
	fmt.Fprintf(w, "%s", sk)
	fmt.Fprintf(w, "%s", "\",\"PK\":{\"X\":\"")
	var pk = GeneratePublicKey(sk)
	fmt.Fprintf(w, "%s", pk.X)
	fmt.Fprintf(w, "%s", "\",\"Y\":\"")
	fmt.Fprintf(w, "%s", pk.Y)
	fmt.Fprintf(w, "%s", "\"}}")
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	ip, err := getIP(r)
	if err != nil {
		log.Print("Serving index.html to ", ip)
	} else {
		log.Print("Serving index.html to ", r.RemoteAddr)
	}
	http.ServeFile(w, r, "./static/index.html")
}

func main() {
	// server
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/sk", newSKHandler)
	http.HandleFunc("/pk", getPKHandler)
	http.HandleFunc("/sign", signHandler)
	http.HandleFunc("/verify", verifyHandler)
	log.Print("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
