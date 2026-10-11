package subtool

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
)

const syntheticNodeUuidForTesting = "00000000-0000-4000-8000-000000000000"

func TestUriCredentialsAndNodeDisplayNameAreDecodedExactlyOnce(testContext *testing.T) {
	password := "p@ss:word+/%40"
	for _, scheme := range []string{"trojan", "hysteria2", "hy2", "anytls"} {
		testContext.Run(scheme, func(testContext *testing.T) {
			rawProtocolUri := (&url.URL{Scheme: scheme, User: url.User(password), Host: "example.org:443", Fragment: "A+B%2F"}).String()
			outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(rawProtocolUri)
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			if outboundConfiguration.Password != password || outboundConfiguration.Tag != "A+B%2F" || outboundConfiguration.TLS == nil || !outboundConfiguration.TLS.Enabled {
				testContext.Fatal("encoded credentials, fragment or implicit TLS changed")
			}
		})
	}
	outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("hy2://user:p%40ss%3Aword@example.org")
	if operationError != nil || outboundConfiguration.Password != "user:p@ss:word" || outboundConfiguration.ServerPort != 443 {
		testContext.Fatal("Hysteria2 userpass or default port mapping failed")
	}
}

func TestHysteria2ShareLinksMapPortRangesAndHopIntervals(testContext *testing.T) {
	for _, rawProtocolUri := range []string{
		"hy2://password@example.org:443,5000-5010?hop_interval=15",
		"hysteria2://password@example.org:443?mport=443,5000-5010&hopInterval=15s",
		"hysteria2://password@[2001:db8::1]:443,5000-5010?hop_interval=15s",
		"hysteria2://password@example.org?server_ports=443,5000:5010&hop_interval=15s",
	} {
		outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(rawProtocolUri)
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		if outboundConfiguration.Type != "hysteria2" || outboundConfiguration.TLS == nil || !outboundConfiguration.TLS.Enabled || outboundConfiguration.ServerPort != 0 || strings.Join(outboundConfiguration.ServerPorts, ",") != "443:443,5000:5010" || outboundConfiguration.HopInterval != "15s" {
			testContext.Fatal("incorrect Hysteria2 port hopping mapping")
		}
	}
	for _, host := range []string{"example.org", "[2001:db8::1]"} {
		outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("hy2://password@" + host)
		if operationError != nil || outboundConfiguration.ServerPort != 443 {
			testContext.Fatal("omitted port did not default to 443")
		}
	}
}

func TestShadowsocksShareLinkFormatsAndPluginConfigurationMapping(testContext *testing.T) {
	password := "p@ss:word+/%40"
	authority := url.UserPassword("aes-128-gcm", password).String() + "@example.org:443"
	for _, rawProtocolUri := range []string{
		"ss://" + authority,
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+password)) + "@example.org:443",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:"+password+"@example.org:443")),
	} {
		outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(rawProtocolUri + "#SS%2B%252F")
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		if outboundConfiguration.Type != "shadowsocks" || outboundConfiguration.EncryptionMethod != "aes-128-gcm" || outboundConfiguration.Password != password || outboundConfiguration.Tag != "SS+%2F" || outboundConfiguration.TLS != nil || outboundConfiguration.Transport != nil {
			testContext.Fatal("incorrect Shadowsocks mapping")
		}
	}
	for _, plugin := range []string{"obfs-local;obfs=http;obfs-host=example.org", "simple-obfs;obfs=tls", "v2ray-plugin;tls;host=example.org;path=/ws"} {
		outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("ss://" + authority + "/?plugin=" + url.QueryEscape(plugin))
		if operationError != nil {
			testContext.Fatal(operationError)
		}
		parts := strings.SplitN(plugin, ";", 2)
		if outboundConfiguration.Plugin == "" || outboundConfiguration.PluginOptions != parts[1] {
			testContext.Fatal("plugin options were dropped")
		}
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("ss://" + url.UserPassword("2022-blake3-aes-256-gcm", key).String() + "@example.org:443")
	if operationError != nil || outboundConfiguration.Password != key {
		testContext.Fatal("SS2022 percent-encoded key changed")
	}
}

func TestVMessShareLinkTransportConfigurationMapping(testContext *testing.T) {
	for _, testCase := range []struct {
		network      string
		expectedHost any
	}{
		{"grpc", nil}, {"ws", nil}, {"h2", []string{"example.org"}}, {"httpupgrade", "example.org"},
	} {
		testContext.Run(testCase.network, func(testContext *testing.T) {
			payload, _ := json.Marshal(map[string]any{"add": "example.org", "port": "443", "id": syntheticNodeUuidForTesting, "aid": "0", "net": testCase.network, "path": "/service", "host": "example.org", "tls": "tls", "fp": "chrome", "alpn": "h2", "packetEncoding": "packetaddr", "allowInsecure": true})
			outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("vmess://" + base64.RawURLEncoding.EncodeToString(payload))
			if operationError != nil {
				testContext.Fatal(operationError)
			}
			if outboundConfiguration.TLS == nil || !outboundConfiguration.TLS.AllowInsecure || outboundConfiguration.TLS.UTLSFingerprint == nil || outboundConfiguration.TLS.ServerNameIndication != "example.org" || outboundConfiguration.PacketEncodingType == nil || *outboundConfiguration.PacketEncodingType != "packetaddr" {
				testContext.Fatal("VMess TLS/packet mapping failed")
			}
			transport, _ := json.Marshal(outboundConfiguration.Transport)
			var fields map[string]any
			_ = json.Unmarshal(transport, &fields)
			switch testCase.network {
			case "grpc":
				if outboundConfiguration.Transport.ServiceName != "/service" || fields["path"] != nil || fields["host"] != nil {
					testContext.Fatal("gRPC emitted HTTP fields")
				}
			case "ws":
				if outboundConfiguration.Transport.Headers["Host"] != "example.org" || fields["host"] != nil {
					testContext.Fatal("WS host mapping failed")
				}
			case "h2":
				if outboundConfiguration.Transport.Type != "http" {
					testContext.Fatal("h2 alias not normalized")
				}
				if _, ok := fields["host"].([]any); !ok {
					testContext.Fatal("HTTP host must be an array")
				}
			case "httpupgrade":
				if fields["host"] != "example.org" || fields["headers"] != nil {
					testContext.Fatal("HTTPUpgrade host must be a string")
				}
			}
		})
	}
	for _, prefix := range []string{"", "wrapped"} {
		rawProtocolUri := "vmess://" + syntheticNodeUuidForTesting + "@example.org:443?security=tls&scy=aes-128-gcm&type=grpc&serviceName=service"
		if prefix != "" {
			rawProtocolUri = "vmess://" + base64.StdEncoding.EncodeToString([]byte(rawProtocolUri))
		}
		outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(rawProtocolUri)
		if operationError != nil || outboundConfiguration.SecurityLayer != "aes-128-gcm" || outboundConfiguration.Transport.ServiceName != "service" {
			testContext.Fatal("VMess query-style link mapping failed")
		}
	}
}

func TestExplicitPacketEncodingParametersOverrideDefaultConfiguration(testContext *testing.T) {
	for _, encoding := range []string{"", "xudp", "packetaddr"} {
		outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("vless://" + syntheticNodeUuidForTesting + "@example.org:443?packet_encoding=" + encoding)
		if operationError != nil || outboundConfiguration.PacketEncodingType == nil || *outboundConfiguration.PacketEncodingType != encoding {
			testContext.Fatal("explicit packet encoding ignored")
		}
		encodedJsonBytes, _ := json.Marshal(outboundConfiguration)
		if !strings.Contains(string(encodedJsonBytes), `"packet_encoding":"`+encoding+`"`) {
			testContext.Fatal("explicit empty packet encoding must survive JSON serialization")
		}
	}
}

func TestAnyTlsIdleSessionConfigurationMapping(testContext *testing.T) {
	outboundConfiguration, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound("anytls://password@example.org:443?idle_session_check_interval=30s&idle_session_timeout=1m&min_idle_session=0")
	if operationError != nil || outboundConfiguration.IdleSessionCheckInterval != "30s" || outboundConfiguration.IdleSessionTimeout != "1m" || outboundConfiguration.MinIdleSession == nil || *outboundConfiguration.MinIdleSession != 0 {
		testContext.Fatal("AnyTLS session options mapping failed")
	}
}

func TestInvalidNodeUrisAreRejectedWithoutExposingPrivateValues(testContext *testing.T) {
	for _, rawProtocolUri := range []string{
		"vless://invalid@example.org:443", "vless://" + syntheticNodeUuidForTesting + "@:443", "vless://" + syntheticNodeUuidForTesting + "@example.org",
		"vless://" + syntheticNodeUuidForTesting + "@example.org:0", "vless://" + syntheticNodeUuidForTesting + "@example.org:65536",
		"vless://" + syntheticNodeUuidForTesting + "@example.org:443?type=xhttp", "vless://" + syntheticNodeUuidForTesting + "@example.org:443?security=unknown",
		"vless://" + syntheticNodeUuidForTesting + "@example.org:443?type=grpc&mode=multi", "vless://" + syntheticNodeUuidForTesting + "@example.org:443?type=tcp&headerType=http",
		"vless://" + syntheticNodeUuidForTesting + "@example.org:443?flow=xtls-rprx-vision&type=ws&security=tls",
		"vless://" + syntheticNodeUuidForTesting + "@example.org:443?packet_encoding=unknown", "vless://" + syntheticNodeUuidForTesting + "@example.org:443?type=ws&ed=-1",
		"trojan://password@example.org:443?insecure=perhaps", "trojan://password@example.org:443?sni=%zz",
		"trojan://password@example.org:443?insecure=0&insecure=1",
		"hy2://password@example.org:443?obfs=unknown", "hy2://password@example.org:443?obfs=salamander",
		"hy2://password@example.org:443?mport=5010-5000", "hy2://password@example.org:0,443",
		"hy2://password@example.org:443?mport=65536", "hy2://password@example.org:443?hop_interval=10s",
		"hy2://password@example.org:443?mport=443&hop_interval=-1s", "hy2://password@example.org:443?pinSHA256=private-token",
		"anytls://password@example.org:443?min_idle_session=-1", "anytls://password@example.org:443?idle_session_timeout=bad",
		"ss://aes-128-gcm:password@example.org:443?plugin=unknown",
	} {
		_, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(rawProtocolUri)
		if operationError == nil {
			testContext.Fatalf("invalid synthetic link accepted: %s", rawProtocolUri)
		}
		for _, private := range []string{"example.org", "private-token", "password", syntheticNodeUuidForTesting} {
			// 固定错误说明可以包含 password 一词，但不能包含输入的密码值。
			if private == "password" {
				continue
			}
			if strings.Contains(operationError.Error(), private) {
				testContext.Fatal("parser error leaked URI contents")
			}
		}
	}
	for _, scheme := range []string{"hysteria", "hy"} {
		_, operationError := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(scheme + "://password@example.org:443")
		if !errors.Is(operationError, ErrUnsupportedHysteriaVersion1ShareLink) {
			testContext.Fatal("Hysteria v1 must be explicitly unsupported")
		}
	}
}

func TestWrappedBase64SubscriptionContentIsDecodedCorrectly(testContext *testing.T) {
	original := "trojan://password@example.org:443\n"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(original))
	decoded, operationError := AttemptRobustBase64DecodingOfSubscriptionContent("\ufeff  " + encoded[:8] + " \n\t" + encoded[8:] + "\r\n")
	if operationError != nil || decoded != original {
		testContext.Fatal("wrapped Base64 subscription decoding failed")
	}
}
