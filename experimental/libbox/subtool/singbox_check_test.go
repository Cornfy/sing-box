package subtool

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSupportedProtocolConfigurationsAreAcceptedBySingBox(testContext *testing.T) {
	singBoxExecutablePath := os.Getenv("SING_BOX_BINARY")
	var operationError error
	if singBoxExecutablePath == "" {
		singBoxExecutablePath, operationError = exec.LookPath("sing-box")
	}
	if operationError != nil {
		testContext.Skip("sing-box is not installed")
	}
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	ssKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	vmessJSON := `{"add":"example.org","port":443,"id":"00000000-0000-4000-8000-000000000000","net":"httpupgrade","path":"/ws","host":"example.org","tls":"tls"}`
	for _, syntheticProtocolUri := range []string{
		"vless://" + syntheticNodeUuidForTesting + "@example.org:443?security=reality&pbk=" + key + "&sid=00&type=grpc&serviceName=service&mode=gun",
		"vless://" + syntheticNodeUuidForTesting + "@example.org:443?packet_encoding=",
		"trojan://p%40ss%3Aword@example.org:443?sni=example.org&type=ws&path=%2Fws&host=example.org",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON)),
		"vmess://" + syntheticNodeUuidForTesting + "@example.org:443?security=tls&type=h2&host=example.org",
		"vmess://" + syntheticNodeUuidForTesting + "@example.org:443?security=tls&type=grpc&serviceName=service",
		"ss://aes-128-gcm:password@example.org:443?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.org",
		"ss://aes-128-gcm:password@example.org:443?plugin=v2ray-plugin%3Bhost%3Dexample.org%3Bpath%3D%2Fws",
		"ss://" + url.UserPassword("2022-blake3-aes-256-gcm", ssKey).String() + "@example.org:443",
		"hy2://password@example.org",
		"hy2://password@example.org:443,5000-5010?hop_interval=15s&obfs=salamander&obfs-password=synthetic",
		"tuic://" + syntheticNodeUuidForTesting + ":password@example.org:443?sni=example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native",
		"anytls://password@example.org:443?sni=example.com&idle_session_check_interval=30s&idle_session_timeout=1m&min_idle_session=0",
	} {
		node, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(syntheticProtocolUri)
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		testContext.Run(node.Type, func(testContext *testing.T) {
			encodedJsonBytes, operationError := json.Marshal(map[string]any{"outbounds": []*StandardSingBoxOutboundConfiguration{node}})
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			path := filepath.Join(testContext.TempDir(), "config.json")
			if operationError = os.WriteFile(path, encodedJsonBytes, 0600); operationError != nil {
				testContext.Fatal(operationError)
			}
			if output, operationError := exec.Command(singBoxExecutablePath, "check", "-c", path).CombinedOutput(); operationError != nil {
				testContext.Fatalf("synthetic config rejected: %v\n%s", operationError, output)
			}
		})
	}
}
