package gopkt

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

// S-tier PTMP protcol specs
// https://github.com/bfranske/pt-python-examples?tab=readme-ov-file

const PTMP_IDENTIFIER = "PTMP"
const PTMP_VERSION = 1

const DEFAULT_IPC_PORT = 39000
const DEFAULT_KEEP_ALIVE_PERIOD = 60

// PMTP Encoding Type
const (
	ENCODING_TEXT   = 1
	ENCODING_BINARY = 2
)

const ENCRYPTION_NONE = 1
const COMPRESSION_NONE = 1

const (
	AUTHENTICATION_CLEARTEXT = 1
	AUTHENTICATION_SIMPLE    = 2
	AUTHENTICATION_MD5       = 4
)

// ARG TYPE
const (
	// Same as PTMP and IPC
	BYTE         = 1
	BOOL         = 2
	SHORT        = 3
	INT          = 4
	LONG         = 5
	FLOAT        = 6
	DOUBLE       = 7
	STRING       = 8
	QSTRING      = 9
	IP_ADDRESS   = 10
	IPV6_ADDRESS = 11
	MAC_ADDRESS  = 12
	UUID         = 13

	// IPC only
	PAIR   = 14
	VECTOR = 15
	DATA   = 16
)

// PTMP Message Types
const (
	PTMP_TYPE_NEGOTIATION_REQUEST      = 0
	PTMP_TYPE_NEGOTIATION_RESPONSE     = 1
	PTMP_TYPE_AUTHENTICATION_REQUEST   = 2
	PTMP_TYPE_AUTHENTICATION_CHALLENGE = 3
	PTMP_TYPE_AUTHENTICATION_RESPONSE  = 4
	PTMP_TYPE_AUTHENTICATION_STATUS    = 5
	PTMP_TYPE_KEEP_ALIVE               = 6
	PTMP_TYPE_DISCONNECT               = 7
	PTMP_TYPE_COMMUNICATION            = 8
	// IPC_MSGS 100 - 199
	// MULTIUSER_MSGS 200 - 299
)

func PrintBytesAsHex(data []byte) {
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			fmt.Print("\\x00")
		} else {
			fmt.Printf("%c", data[i])
		}
	}
	fmt.Println()
}

func readStr(reader *bufio.Reader, fieldName string) string {
	str, err := reader.ReadString(0)
	if err != nil {
		log.Fatal("Error reading negotiation response - ", fieldName, ": ", err)
	}
	return str[:len(str)-1]
}

func readInt(reader *bufio.Reader, fieldName string) int {
	str, err := reader.ReadString(0)
	if err != nil {
		log.Fatal("Error reading negotiation response - ", fieldName, ": ", err)
	}
	value, err := strconv.Atoi(str[:len(str)-1])
	if err != nil {
		log.Fatal("Error parsing negotiation response - ", fieldName, ": ", err)
	}
	return value
}

func readBool(reader *bufio.Reader, fieldName string) bool {
	str, err := reader.ReadString(0)
	if err != nil {
		log.Fatal("Error reading ", fieldName, ": ", err)
	}
	if len(str) < 2 {
		// log.Fatal("Error parsing ", fieldName, ": invalid length")
		return false
	}
	value, err := strconv.ParseBool(str[:len(str)-1])
	if err != nil {
		log.Fatal("Error parsing ", fieldName, ": ", err)
	}
	return value
}

type PtmpConnection interface {
	SendNegotiationRequest(info PtmpNegotiationInfo)
	ReceiveNegotiationResponse() PtmpNegotiationInfo

	SendAuthenticationRequest(info PtmpAuthenticationRequestInfo)
	ReceiveAuthenticationChallenge() PtmpAuthenticationChallengeInfo
	SendAuthenticationResponse(info PtmpAuthenticationResponseInfo)
	ReceiveAuthenticationStatus() PtmpAuthenticationStatusInfo

	Disconnect(reason string)
}

func NewPtmpConnection(serverAddress string) net.Conn {
	log.Println("Connecting to PTMP server at", serverAddress)

	// Connect to server
	conn, err := net.Dial("tcp", serverAddress)
	if err != nil {
		log.Fatal("Error connecting to PTMP server:", err)
	}

	log.Println("Connected to ", serverAddress)

	return conn
}

// negotitation of auth method

type PtmpNegotiationInfo struct {
	Identifier      string
	Version         int
	AppId           string
	Encoding        int
	Encryption      int
	Compression     int
	Authentication  int
	Timestamp       string
	KeepAlivePeriod int
	Reserved        string
}

func SendNegotiationRequest(conn *net.Conn, info PtmpNegotiationInfo) {
	log.Println("Sending negotiation request...")

	// timestamp := time.Now().Format("20060102150405")
	// reserved := ":PTVER8.0.0.0000" // Example version

	// info := PtmpNegotiationInfo{
	// 	identifier:      PTMP_IDENTIFIER,
	// 	version:         PTMP_VERSION,
	// 	appId:           appId,
	// 	encoding:        TEXT_ENCODING,
	// 	encryption:      ENCRYPTION_NONE,
	// 	compression:     COMPRESSION_NONE,
	// 	authType:        authType,
	// 	timestamp:       timestamp,
	// 	keepAlivePeriod: KEEP_ALIVE_PERIOD,
	// 	reserved:        reserved,
	// }

	negotiationString := fmt.Sprintf(
		"%s\x00%d\x00{%s}\x00%d\x00%d\x00%d\x00%d\x00%s\x00%d\x00%s\x00",
		info.Identifier,
		info.Version,
		info.AppId,
		info.Encoding,
		info.Encryption,
		info.Compression,
		info.Authentication,
		info.Timestamp,
		info.KeepAlivePeriod,
		info.Reserved,
	)
	encodedValue := []byte(negotiationString + "\x00")

	msgType := []byte(fmt.Sprintf("%d\x00", PTMP_TYPE_NEGOTIATION_REQUEST))
	msgLen := []byte(fmt.Sprintf("%d\x00", len(msgType)+len(encodedValue)))

	request := append(msgLen, msgType...)
	request = append(request, encodedValue...)

	PrintBytesAsHex(request)

	n, err := (*conn).Write(request)
	if err != nil {
		log.Fatal("Error sending negotiation request:", err)
	}

	log.Printf("Negotiation request sent. Bytes sent: %d", n)
}

func ReceiveNegotiationResponse(conn *net.Conn) PtmpNegotiationInfo {
	log.Println("Waiting for negotiation response...")
	reader := bufio.NewReader(*conn)

	msgType := readInt(reader, "type")
	log.Printf("Message Type: %d", msgType)
	msgLen := readInt(reader, "length")
	log.Printf("Message Length: %d", msgLen)

	identifier := readStr(reader, "Identifier")
	version := readInt(reader, "Version")
	appId := readStr(reader, "App ID")
	encoding := readInt(reader, "Encoding")
	encryption := readInt(reader, "Encryption")
	compression := readInt(reader, "Compression")
	authentication := readInt(reader, "Authentication Type")
	timestamp := readStr(reader, "Timestamp")
	keepAlive := readInt(reader, "Keep Alive Period")
	reserved := readStr(reader, "Reserved")

	info := PtmpNegotiationInfo{
		Identifier:      identifier,
		Version:         version,
		AppId:           appId,
		Encoding:        encoding,
		Encryption:      encryption,
		Compression:     compression,
		Authentication:  authentication,
		Timestamp:       timestamp,
		KeepAlivePeriod: keepAlive,
		Reserved:        reserved,
	}

	log.Println("Negotiation response received.")
	log.Printf("PTMP Identifier: %s", info.Identifier)
	log.Printf("PTMP Version: %d", info.Version)
	log.Printf("App ID: %s", info.AppId)
	log.Printf("Encoding: %d", info.Encoding)
	log.Printf("Encryption: %d", info.Encryption)
	log.Printf("Compression: %d", info.Compression)
	log.Printf("Authentication Type: %d", info.Authentication)
	log.Printf("Timestamp: %s", info.Timestamp)
	log.Printf("Keep Alive Period: %d", info.KeepAlivePeriod)
	log.Printf("Reserved: %s", info.Reserved)

	return info
}

// auth method

type PtmpAuthenticationRequestInfo struct {
	Username string
}

func SendAuthenticationRequest(conn *net.Conn, info PtmpAuthenticationRequestInfo) {
	log.Println("Sending authentication request...")

	encodedValue := []byte(fmt.Sprintf("%s\x00", info.Username))

	msgType := []byte(fmt.Sprintf("%d\x00", PTMP_TYPE_AUTHENTICATION_REQUEST))
	msgLen := []byte(fmt.Sprintf("%d\x00", len(msgType)+len(encodedValue)))

	request := append(msgLen, msgType...)
	request = append(request, encodedValue...)

	PrintBytesAsHex(request)

	n, err := (*conn).Write(request)
	if err != nil {
		log.Fatal("Error sending authentication request:", err)
	}
	log.Printf("Authentication request sent. Bytes sent: %d", n)
}

type PtmpAuthenticationChallengeInfo struct {
	Challenge string
}

func ReceiveAuthenticationChallenge(conn *net.Conn) PtmpAuthenticationChallengeInfo {
	log.Println("Waiting for authentication response...")

	reader := bufio.NewReader(*conn)

	msgLen := readInt(reader, "length")
	msgType := readInt(reader, "type")
	challenge := readStr(reader, "challenge")

	log.Println("Receiving authentication challenge")
	log.Printf("Message Length: %d", msgLen)
	log.Printf("Message Type: %d", msgType)
	log.Printf("Challenge: %s", challenge)

	return PtmpAuthenticationChallengeInfo{
		Challenge: challenge,
	}
}

type PtmpAuthenticationResponseInfo struct {
	Username string
	Digest   string
	Custom   string
}

func SendAuthenticationResponse(conn *net.Conn, info PtmpAuthenticationResponseInfo) {
	log.Println("Sending authentication response...")

	encodedValue := []byte(fmt.Sprintf("%s\x00%s\x00%s\x00", info.Username, info.Digest, info.Custom))
	msgType := []byte(fmt.Sprintf("%d\x00", PTMP_TYPE_AUTHENTICATION_RESPONSE))
	msgLen := []byte(fmt.Sprintf("%d\x00", len(msgType)+len(encodedValue)))

	request := append(msgLen, msgType...)
	request = append(request, encodedValue...)

	PrintBytesAsHex(request)

	n, err := (*conn).Write(request)
	if err != nil {
		log.Fatal("Error sending authentication response:", err)
	}
	log.Printf("Authentication response sent. Bytes sent: %d", n)
}

type PtmpAuthenticationStatusInfo struct {
	Status bool
}

func ReceiveAuthenticationStatus(conn *net.Conn) PtmpAuthenticationStatusInfo {
	log.Println("Waiting for authentication status...")
	reader := bufio.NewReader(*conn)

	msgLen := readInt(reader, "length")
	msgType := readInt(reader, "type")
	status := readBool(reader, "status")

	log.Println("Receiving authentication status")
	log.Printf("Message Length: %d", msgLen)
	log.Printf("Message Type: %d", msgType)
	log.Printf("Status: %t", status)

	return PtmpAuthenticationStatusInfo{
		Status: status,
	}
}

func Disconnect(conn *net.Conn, reason string) {
	log.Println("Closing PTMP connection...")

	encodedValue := []byte(fmt.Sprintf("%s\x00", reason))
	msgType := []byte(fmt.Sprintf("%d\x00", PTMP_TYPE_DISCONNECT))
	msgLen := []byte(fmt.Sprintf("%d\x00", len(msgType)+len(encodedValue)))

	request := append(msgLen, msgType...)
	request = append(request, encodedValue...)

	PrintBytesAsHex(request)

	n, err := (*conn).Write(request)
	if err != nil {
		log.Fatal("Error sending disconnect message:", err)
	}
	log.Printf("Disconnect message sent. Bytes sent: %d", n)

	err = (*conn).Close()
	if err != nil {
		log.Fatal("Error closing PTMP connection:", err)
	}
	log.Println("PTMP connection closed.")
}

type PtmpIpcData struct {
	TypeId int
	Value  interface{}
}

type PtmpIpcCallInfo struct {
	CallId   int
	CallName string
	Args     []PtmpIpcData
}

func SendIPCCall(conn *net.Conn, info PtmpIpcCallInfo) {
	log.Println("Sending IPC call...")

	// # 3. Send a basic IPC API request without any arguments/parameters
	// call_id = 1 # int number to differentiate responses
	// call_name = "appWindow\0 0 \0getVersion" # IPC call ipc.appWindow().getVersion(), note the strange formatting
	// print("Sending IPC call...")
	// ipc_call_string = f"{call_id}\0{call_name}\0 0 \0"
	// encoded_value = ipc_call_string.encode('utf-8')
	// type = str(100).encode('utf-8') + b'\0' # PTMP message type is between 100 and 199 for IPC call messages
	// length = str(len(type+encoded_value)).encode('utf-8') + b'\0'
	// request = length+type+encoded_value
	// print("IPC Call sent.")
	// print(request)
	// sock.sendall(request)
	// print("Receiving IPC Response...")
	// try:
	//     while True:
	//         data = sock.recv(1024)
	//         if not data:
	//             break
	//         print(f"Received: {data}")
	// except socket.timeout:
	//     pass

	// no args
	// ipcCallStr := fmt.Sprintf("%s\x00%s\x00 0 \x00", info.CallId, info.CallName)

	// 1 arg
	// ipcCallStr := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00 0 \x00", info.CallId, info.CallName, info.Args[0].type, info.Args[0].value)

	// 2 args
	// ipcCallStr := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%d\x00%s\x00 0 \x00", info.CallId, info.CallName, info.Args[0].(int), info.Args[1].(string), info.Args[2].(int), info.Args[3].(string))

	// callName
	// appWindow.getVersion -> appWindow\x00 0 \x00getVersion

	// n args
	ipCallStr := fmt.Sprintf("%d\x00", info.CallId)

	callNameParts := strings.Split(info.CallName, ".")
	for i, part := range callNameParts {
		ipCallStr += part + "\x00"

		if i < len(callNameParts)-1 {
			ipCallStr += " 0 \x00"
		}
	}

	for _, arg := range info.Args {
		ipCallStr += fmt.Sprintf("%d\x00%v\x00", arg.TypeId, arg.Value)
	}
	ipCallStr += " 0 \x00"

	log.Println("IPC Call String:", ipCallStr)

	encodedValue := []byte(ipCallStr)

	msgType := []byte(fmt.Sprintf("%d\x00", 100))
	msgLen := []byte(fmt.Sprintf("%d\x00", len(msgType)+len(encodedValue)))

	request := append(msgLen, msgType...)
	request = append(request, encodedValue...)

	PrintBytesAsHex(request)

	n, err := (*conn).Write(request)
	if err != nil {
		log.Fatal("Error sending IPC call:", err)
	}
	log.Printf("IPC call sent. Bytes sent: %d", n)
}

type PtmpIpcCallResponseInfo struct {
	CallId int
	Rets   []PtmpIpcData
}

func ReceiveIPCCallResponse(conn *net.Conn) PtmpIpcCallResponseInfo {
	log.Println("Waiting for IPC response...")
	reader := bufio.NewReader(*conn)

	msgLen := readInt(reader, "length")
	log.Printf("Message Length: %d", msgLen)

	msgType := readInt(reader, "type")
	log.Printf("Message Type: %d", msgType)

	callId := readInt(reader, "ipc call id")
	log.Printf("IPC Call Id: %d", callId)

	rets := make([]PtmpIpcData, 0)

	// read the rest of the message
	// calc how much the pointer has moved n compare with length
	currLen := len(fmt.Sprintf("%d\x00", msgType)) + len(fmt.Sprintf("%d\x00", callId))

	for {
		if currLen >= msgLen {
			break
		}

		typeId, err := reader.ReadString(0)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal("Error reading IPC call response - type id: ", err)
		}

		typeIdInt, err := strconv.Atoi(typeId[:len(typeId)-1])
		if err != nil {
			log.Fatal("Error parsing IPC call response - type id: ", err)
		}

		switch typeIdInt {
		case BYTE, BOOL, SHORT, INT, LONG, FLOAT, DOUBLE:
		case STRING, QSTRING, IP_ADDRESS, IPV6_ADDRESS, MAC_ADDRESS, UUID:
			value, err := reader.ReadString(0)
			if err != nil {
				log.Fatal("Error reading IPC call response - value: ", err)
			}
			valueStr := value[:len(value)-1]

			log.Printf("Return Value - Type ID: %d, Value: %s", typeIdInt, valueStr)
			rets = append(rets, PtmpIpcData{
				TypeId: typeIdInt,
				Value:  valueStr,
			})

			currLen += len(typeId) + len(value)
		case VECTOR:
			vectorLen := readInt(reader, "vector length")
			log.Printf("Vector Length: %d", vectorLen)
			currLen += len(typeId) + len(fmt.Sprintf("%d\x00", vectorLen))

			vectorDataType := readInt(reader, "vector data type")
			log.Printf("Vector Data Type: %d", vectorDataType)
			currLen += len(fmt.Sprintf("%d\x00", vectorDataType))

			// log.Fatal("Error: complex types not supported yet - type id: ", typeIdInt)
		case PAIR, DATA:
			log.Fatal("Error: complex types not supported yet - type id: ", typeIdInt)
		}
	}

	return PtmpIpcCallResponseInfo{
		CallId: callId,
		Rets:   rets,
	}
}
