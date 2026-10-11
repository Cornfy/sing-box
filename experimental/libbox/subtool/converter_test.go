package subtool

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestRealityShareLinkParameterAliasesAndConfigurationMapping(testContext *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, testCase := range []struct{ name, params, fingerprint, shortID string }{
		{"standard", "pbk=" + key + "&sid=0123&fp=firefox&sni=example.com", "firefox", "0123"},
		{"camel case", "publicKey=" + key + "&shortId=abcd&fingerprint=chrome&serverName=example.com", "chrome", "abcd"},
		{"snake case default fingerprint empty short ID", "public_key=" + key + "&server_name=example.com", "chrome", ""},
		{"standard precedence", "pbk=" + key + "&publicKey=invalid&sid=abcd&shortId=invalid&sni=example.com&serverName=other.example&fp=firefox&fingerprint=chrome", "firefox", "abcd"},
	} {
		testContext.Run(testCase.name, func(testContext *testing.T) {
			node, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("vless://00000000-0000-4000-8000-000000000000@example.org:443?security=reality&type=tcp&flow=xtls-rprx-vision&" + testCase.params + "#Reality")
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			if node.TLS == nil || !node.TLS.Enabled || node.TLS.ServerNameIndication != "example.com" {
				testContext.Fatalf("incorrect TLS: %+v", node.TLS)
			}
			if node.TLS.RealitySecurity.PublicKeyBase64 != key || node.TLS.RealitySecurity.ShortIdHex != testCase.shortID || !node.TLS.RealitySecurity.Enabled {
				testContext.Fatal("incorrect Reality mapping")
			}
			if node.TLS.UTLSFingerprint == nil || !node.TLS.UTLSFingerprint.Enabled || node.TLS.UTLSFingerprint.Fingerprint != testCase.fingerprint {
				testContext.Fatal("incorrect uTLS mapping")
			}
			if node.Transport != nil || node.FlowControl != "xtls-rprx-vision" || node.UUID != "00000000-0000-4000-8000-000000000000" {
				testContext.Fatal("incorrect VLESS mapping")
			}
			encodedJsonBytes, operationError := json.Marshal(node)
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			if !strings.Contains(string(encodedJsonBytes), `"public_key":"`+key+`"`) || strings.Contains(string(encodedJsonBytes), `"security":"reality"`) {
				testContext.Fatal("incorrect sing-box JSON")
			}
		})
	}
}

func TestRealityShareLinksRejectInvalidPublicKeysAndShortIds(testContext *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, params := range []string{"sid=00", "pbk=secret-value&sid=00", "pbk=" + url.QueryEscape(key+"=") + "&sid=00", "pbk=" + key + "&sid=1", "pbk=" + key + "&sid=zz", "pbk=" + key + "&sid=0123456789abcdef00"} {
		_, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("vless://id@example.org:443?security=reality&" + params)
		if operationError == nil {
			testContext.Fatalf("expected error for %s", params)
		}
		if strings.Contains(operationError.Error(), "secret-value") {
			testContext.Fatal("error leaks key")
		}
	}
}

func TestOrdinaryTlsShareLinksPreserveConfigurationWithoutReality(testContext *testing.T) {
	node, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("trojan://password@example.org:443?sni=example.com&fp=firefox")
	if operationError != nil {
		testContext.Fatal(operationError)
	}
	if node.TLS == nil || node.TLS.RealitySecurity != nil || node.Password != "password" {
		testContext.Fatal("ordinary TLS changed")
	}
}

func TestSubscriptionFailureCategoriesDoNotExposePrivateInputValues(testContext *testing.T) {
	cases := []struct {
		syntheticProtocolUri string
		operationError       error
		want                 string
	}{
		{"vless://private-uuid@private-host?pbk=private-key", ErrInvalidRealityPublicKey, "Reality 公钥缺失或格式无效"},
		{"vless://private-uuid@private-host?sid=private-id", ErrInvalidRealityShortId, "Reality Short ID 格式无效"},
		{"vless://private-host%zz", nil, "已支持协议的 URI 或编码无效"},
		{"unsupported://private-password@private-host", nil, "不支持的协议或链接"},
		{"tuic://private-password@private-host", nil, "已支持协议的 URI 或编码无效"},
		{"https://private-host/private-token", nil, "HTTP/HTTPS 链接（未作为节点解析）"},
		{"VLESS://private-uuid@private-host", nil, "已支持协议的名称大小写不兼容"},
		{"private subscription notice", nil, "非节点内容或无法识别的格式"},
	}
	for _, testCase := range cases {
		got := DetermineSubscriptionRecordFailureCategoryFromConversionError(testCase.syntheticProtocolUri, testCase.operationError)
		if got != testCase.want {
			testContext.Fatalf("unexpected fixed category: %q", got)
		}
	}
}

func TestHysteria2ConfigurationsDoNotContainUuidFields(testContext *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2"} {
		node, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(scheme + "://synthetic-password@example.org:443?sni=example.com")
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		if node.Type != "hysteria2" || node.Password != "synthetic-password" || node.UUID != "" {
			testContext.Fatal("incorrect hysteria2 credentials")
		}
		encodedJsonBytes, operationError := json.Marshal(node)
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		var fields map[string]json.RawMessage
		if operationError = json.Unmarshal(encodedJsonBytes, &fields); operationError != nil {
			testContext.Fatal(operationError)
		}
		if _, exists := fields["uuid"]; exists {
			testContext.Fatal("hysteria2 must not emit uuid")
		}
	}
}

func TestTuicVersion5ShareLinkConfigurationMapping(testContext *testing.T) {
	node, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("tuic://00000000-0000-4000-8000-000000000000:p%40ss%3Aword@example.org:443?sni=example.com&alpn=h3%2Ch2&insecure=true&congestion_control=bbr&udp_relay_mode=quic#Synthetic")
	if operationError != nil {
		testContext.Fatal(operationError)
	}
	if node.Type != "tuic" || node.UUID != "00000000-0000-4000-8000-000000000000" || node.Password != "p@ss:word" {
		testContext.Fatal("incorrect TUIC credentials")
	}
	if node.CongestionControl != "bbr" || node.UDPRelayMode != "quic" || node.PacketEncodingType != nil || node.Transport != nil {
		testContext.Fatal("incorrect TUIC options")
	}
	if node.TLS == nil || !node.TLS.Enabled || !node.TLS.AllowInsecure || node.TLS.ServerNameIndication != "example.com" || len(node.TLS.NextProtocolsNegotiation) != 2 {
		testContext.Fatal("incorrect TUIC TLS")
	}
}

func TestAnyTlsShareLinkConfigurationMapping(testContext *testing.T) {
	node, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("anytls://p%40ss%3Aword@example.org:443?sni=example.com&peer=other.example&allow_insecure=1#Synthetic")
	if operationError != nil {
		testContext.Fatal(operationError)
	}
	if node.Type != "anytls" || node.Password != "p@ss:word" || node.UUID != "" || node.Transport != nil {
		testContext.Fatal("incorrect AnyTLS credentials")
	}
	if node.TLS == nil || !node.TLS.Enabled || !node.TLS.AllowInsecure || node.TLS.ServerNameIndication != "example.com" {
		testContext.Fatal("incorrect AnyTLS TLS")
	}
	peer, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("anytls://password@example.org:443?peer=example.com")
	if operationError != nil || peer.TLS.ServerNameIndication != "example.com" {
		testContext.Fatal("AnyTLS peer fallback failed")
	}
}

func TestTuicAndAnyTlsShareLinksRejectUnsupportedOptionsAndCredentials(testContext *testing.T) {
	for _, query := range []string{"congestion_control=invalid", "udp_relay_mode=invalid", "udp_relay_mode=native&udp_over_stream=true"} {
		_, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("tuic://00000000-0000-4000-8000-000000000000:password@example.org:443?" + query)
		if operationError == nil {
			testContext.Fatal("accepted invalid TUIC options")
		}
	}
	for _, syntheticProtocolUri := range []string{"tuic://id@example.org:443", "anytls://user:password@example.org:443"} {
		if _, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(syntheticProtocolUri); operationError == nil {
			testContext.Fatal("accepted ambiguous credentials")
		}
	}
}
