package main

import (
	"fmt"
	"time"

	"gopkt"

	"github.com/google/uuid"
)

const USERNAME = "net.ihitc.ptmptest"
const PASSWORD = "cisco"

func main() {
	SERVER_ADDRESS := fmt.Sprintf("127.0.0.1:%d", gopkt.DEFAULT_IPC_PORT)
	APP_ID := uuid.New().String()

	conn := gopkt.NewPtmpConnection(SERVER_ADDRESS)
	defer gopkt.Disconnect(&conn, "Finished")

	gopkt.SendNegotiationRequest(
		&conn,
		gopkt.PtmpNegotiationInfo{
			Identifier:      gopkt.PTMP_IDENTIFIER,
			Version:         gopkt.PTMP_VERSION,
			AppId:           APP_ID,
			Encoding:        gopkt.ENCODING_TEXT,
			Encryption:      gopkt.ENCRYPTION_NONE,
			Compression:     gopkt.COMPRESSION_NONE,
			Authentication:  gopkt.AUTHENTICATION_CLEARTEXT,
			Timestamp:       time.Now().Format("20060102150405"),
			KeepAlivePeriod: gopkt.DEFAULT_KEEP_ALIVE_PERIOD,
			Reserved:        ":PTVER8.0.0.0000",
		})
	_ = gopkt.ReceiveNegotiationResponse(&conn)

	gopkt.SendAuthenticationRequest(&conn, gopkt.PtmpAuthenticationRequestInfo{
		Username: USERNAME,
	})
	_ = gopkt.ReceiveAuthenticationChallenge(&conn)

	// For simplicity, we are not computing a real digest here
	digest := PASSWORD
	reserved := ""
	gopkt.SendAuthenticationResponse(&conn, gopkt.PtmpAuthenticationResponseInfo{
		Username: USERNAME,
		Digest:   digest,
		Custom:   reserved,
	})
	_ = gopkt.ReceiveAuthenticationStatus(&conn)

	gopkt.SendIPCCall(&conn, gopkt.PtmpIpcCallInfo{
		CallId:   1,
		CallName: "appWindow.getVersion",
	})
	_ = gopkt.ReceiveIPCCallResponse(&conn)

	// gopkt.SendIPCCall(&conn, gopkt.PtmpIpcCallInfo{
	// 	CallId:   2,
	// 	CallName: "appWindow.writeToPT",
	// 	Args: []gopkt.PtmpIpcData{
	// 		{
	// 			TypeId: gopkt.QSTRING,
	// 			Value:  "Hello from PTMP Go client!",
	// 		},
	// 	},
	// })
	// _ = gopkt.ReceiveIPCCallResponse(&conn)1

	gopkt.SendIPCCall(&conn, gopkt.PtmpIpcCallInfo{
		CallId:   3,
		CallName: "appWindow.getActiveWorkspace.getLogicalWorkspace",
	})
	_ = gopkt.ReceiveIPCCallResponse(&conn)
}
