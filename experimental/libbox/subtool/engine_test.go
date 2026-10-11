package subtool

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestProcessTemplateNewProtocols(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	records := strings.Join([]string{
		"vless://00000000-0000-4000-8000-000000000000@example.org:443?security=reality&pbk=" + key + "&sni=example.com&type=grpc&serviceName=update#HK-Reality",
		"hysteria2://password@example.org:443?sni=example.com#HK-Hysteria2",
		"tuic://00000000-0000-4000-8000-000000000000:password@example.org:443?sni=example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#HK-TUIC",
		"anytls://password@example.org:443?sni=example.com&udp=1#HK-AnyTLS",
	}, "\n")
	for _, encoded := range []bool{false, true} {
		name := "plain"
		if encoded {
			name = "base64"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 部分订阅服务会根据 User-Agent 返回完整配置，需要与独立工具保持一致。
				if r.UserAgent() != "Go-http-client/1.1" {
					_, _ = w.Write([]byte(`{"outbounds":[]}`))
					return
				}
				content := records
				if encoded {
					content = base64.StdEncoding.EncodeToString([]byte(content))
				}
				_, _ = w.Write([]byte(content))
			}))
			defer server.Close()
			template, err := json.Marshal(map[string]any{
				"_extra":    map[string]any{"sub_urls": [][]string{{"Synthetic", server.URL}}, "regions": [][]string{{"Region", "HK"}}},
				"outbounds": []any{map[string]any{"type": "selector", "tag": "Proxy", "outbounds": []string{"<all-proxies>", "<all-region-groups>"}}, "<dynamic-region-groups>"},
			})
			if err != nil {
				t.Fatal(err)
			}
			output, err := ProcessTemplateString(string(template))
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Extra     json.RawMessage                        `json:"_extra"`
				Outbounds []StandardSingBoxOutboundConfiguration `json:"outbounds"`
			}
			if err = json.Unmarshal([]byte(output), &result); err != nil {
				t.Fatal(err)
			}
			if result.Extra != nil || len(result.Outbounds) != 6 {
				t.Fatal("template injection failed")
			}
			if len(result.Outbounds[0].Outbounds) != 5 || len(result.Outbounds[1].Outbounds) != 4 {
				t.Fatal("group expansion failed")
			}
			counts := map[string]int{}
			for _, node := range result.Outbounds {
				counts[node.Type]++
				if node.Type == "hysteria2" && node.UUID != "" {
					t.Fatal("hysteria2 UUID leaked")
				}
			}
			for _, protocol := range []string{"vless", "hysteria2", "tuic", "anytls"} {
				if counts[protocol] != 1 {
					t.Fatalf("missing protocol: %s", protocol)
				}
			}
		})
	}
}

func TestTemplateCompilationPreservesEncodedCredentialsAndPortHopping(testContext *testing.T) {
	syntheticPassword := `p@ss:word+/%40\u003c"<>&[  secret  ]`
	rawTrojanUri := (&url.URL{Scheme: "trojan", User: url.User(syntheticPassword), Host: "example.org:443", Fragment: "Special"}).String()
	syntheticSubscriptionContent := rawTrojanUri + "\nhy2://password@example.org:443,5000-5010?hop_interval=15s#Hopping"
	subscriptionServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, subscriptionRequest *http.Request) {
		_, _ = responseWriter.Write([]byte(base64.RawURLEncoding.EncodeToString([]byte(syntheticSubscriptionContent))))
	}))
	defer subscriptionServer.Close()
	syntheticTemplateBytes, encodingError := json.Marshal(map[string]any{
		"_extra":    map[string]any{"sub_urls": [][]string{{"Synthetic", subscriptionServer.URL}}},
		"outbounds": []any{},
	})
	if encodingError != nil {
		testContext.Fatal(encodingError)
	}
	compiledConfigurationString, compilationError := ProcessTemplateString(string(syntheticTemplateBytes))
	if compilationError != nil {
		testContext.Fatal(compilationError)
	}
	var compiledConfiguration struct {
		Outbounds []StandardSingBoxOutboundConfiguration `json:"outbounds"`
	}
	if decodingError := json.Unmarshal([]byte(compiledConfigurationString), &compiledConfiguration); decodingError != nil {
		testContext.Fatal(decodingError)
	}
	if len(compiledConfiguration.Outbounds) != 2 {
		testContext.Fatal("missing synthetic nodes")
	}
	if compiledConfiguration.Outbounds[0].Password != syntheticPassword {
		testContext.Fatal("template compilation changed credentials")
	}
	hysteriaConfiguration := compiledConfiguration.Outbounds[1]
	if hysteriaConfiguration.TLS == nil || !hysteriaConfiguration.TLS.Enabled || strings.Join(hysteriaConfiguration.ServerPorts, ",") != "443:443,5000:5010" || hysteriaConfiguration.HopInterval != "15s" {
		testContext.Fatal("template compilation lost port hopping or implicit TLS")
	}
}
