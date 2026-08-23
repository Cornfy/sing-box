package subtool

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// StandardSingBoxOutboundConfiguration 定义了符合 sing-box 1.11+ 标准的出站配置全量字段
type StandardSingBoxOutboundConfiguration struct {
	Type                  string                               `json:"type"`
	Tag                   string                               `json:"tag"`
	ServerAddress         string                               `json:"server,omitempty"`
	ServerPort            int                                  `json:"server_port,omitempty"`
	EncryptionMethod      string                               `json:"method,omitempty"`
	Password              string                               `json:"password,omitempty"`
	UUID                  string                               `json:"uuid,omitempty"`
	SecurityLayer         string                               `json:"security,omitempty"`
	VmessAlterId          int                                  `json:"alter_id,omitempty"`
	FlowControl           string                               `json:"flow,omitempty"`
	PacketEncodingType    string                               `json:"packet_encoding,omitempty"`
	TLS                   *TransportLayerSecurityConfiguration `json:"tls,omitempty"`
	Transport             *V2RayTransportLayerConfiguration    `json:"transport,omitempty"`
	Obfuscation           *Hysteria2ObfuscationConfiguration   `json:"obfs,omitempty"`
	UploadBandwidthMbps   int                                  `json:"up_mbps,omitempty"`
	DownloadBandwidthMbps int                                  `json:"down_mbps,omitempty"`
	AuthenticationString  string                               `json:"auth_str,omitempty"`
	
	// 以下字段通常用于 sing-box 的动态分组 (urltest/selector)
	ConnectivityTestUrl   string                               `json:"url,omitempty"`
	TestInterval          string                               `json:"interval,omitempty"`
	ToleranceValue        interface{}                          `json:"tolerance,omitempty"`
	Outbounds             []string                             `json:"outbounds,omitempty"`
}

type TransportLayerSecurityConfiguration struct {
	Enabled                     bool                                  `json:"enabled"`
	ServerNameIndication        string                                `json:"server_name,omitempty"`
	AllowInsecure               bool                                  `json:"insecure,omitempty"`
	NextProtocolsNegotiation    []string                              `json:"alpn,omitempty"`
	DisableServerNameIndication bool                                  `json:"disable_sni,omitempty"`
	UTLSFingerprint             *UserAgentTlsFingerprintConfiguration `json:"utls,omitempty"`
	RealitySecurity             *RealitySecurityProtocolConfiguration `json:"reality,omitempty"`
}

type UserAgentTlsFingerprintConfiguration struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RealitySecurityProtocolConfiguration struct {
	Enabled         bool   `json:"enabled"`
	PublicKeyBase64 string `json:"public_key,omitempty"`
	ShortIdHex      string `json:"short_id,omitempty"`
}

type V2RayTransportLayerConfiguration struct {
	Type                string            `json:"type"`
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	ServiceName         string            `json:"service_name,omitempty"`
	MaxEarlyData        int               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string            `json:"early_data_header_name,omitempty"`
	Host                []string          `json:"host,omitempty"`
}

type Hysteria2ObfuscationConfiguration struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

// RawVMessJsonLegacyFormat 对应旧版 VMess 订阅中常见的 JSON 导入格式
type RawVMessJsonLegacyFormat struct {
	Address     string      `json:"add"`
	Port        interface{} `json:"port"`
	ID          string      `json:"id"`
	AlterId     interface{} `json:"aid"`
	Security    string      `json:"scy"`
	Network     string      `json:"net"`
	HeaderType  string      `json:"type"`
	Host        string      `json:"host"`
	Path        string      `json:"path"`
	TlsEnabled  string      `json:"tls"`
	Sni         string      `json:"sni"`
	DisplayName string      `json:"ps"`
}

// AttemptRobustBase64DecodingOfSubscriptionContent 兼容标准 Base64 及 URL 安全变体的解码器
func AttemptRobustBase64DecodingOfSubscriptionContent(rawBase64Input string) (string, error) {
	sanitizedBase64 := strings.TrimSpace(rawBase64Input)
	// 替换 URL 安全字符回标准 Base64 字符
	sanitizedBase64 = strings.ReplaceAll(sanitizedBase64, "-", "+")
	sanitizedBase64 = strings.ReplaceAll(sanitizedBase64, "_", "/")
	
	// 补全 Base64 填充符 '='
	for len(sanitizedBase64)%4 != 0 {
		sanitizedBase64 += "="
	}
	
	decodedBytes, decodingError := base64.StdEncoding.DecodeString(sanitizedBase64)
	return string(decodedBytes), decodingError
}

// SafeConvertInterfaceToInteger 将 interface{} 类型的数值安全转换为标准的 int 类型
func SafeConvertInterfaceToInteger(arbitraryValue interface{}) int {
	switch typedValue := arbitraryValue.(type) {
	case float64:
		return int(typedValue)
	case string:
		integerResult, _ := strconv.Atoi(typedValue)
		return integerResult
	case int:
		return typedValue
	default:
		return 0
	}
}

// ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound 主解析入口，将单行协议 URI 转换为 Sing-box 出站对象
func ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(rawUri string) (*StandardSingBoxOutboundConfiguration, error) {
	if strings.HasPrefix(rawUri, "vmess://") {
		return convertVMessUriIntoSingBoxOutbound(rawUri)
	}
	
	supportedProtocolSchemes := []string{"vless", "trojan", "ss", "hysteria2", "hy2", "hysteria"}
	for _, schemePrefix := range supportedProtocolSchemes {
		if strings.HasPrefix(rawUri, schemePrefix+"://") {
			return extractOutboundConfigurationFromQueryStyleUri(schemePrefix, rawUri)
		}
	}
	return nil, fmt.Errorf("不支持的协议方案或无效的 URI")
}

func constructTlsConfigurationFromUriParameters(protocolType string, uriQueryParameters url.Values) *TransportLayerSecurityConfiguration {
	securityFieldValue := strings.ToLower(uriQueryParameters.Get("security"))
	tlsEnabledParameter := strings.ToLower(uriQueryParameters.Get("tls"))
	
	// 某些协议默认隐含了 TLS
	isProtocolRequiringImplicitTls := protocolType == "trojan" || protocolType == "hysteria2" || 
		protocolSchemeIsHysteriaVariant(protocolType) || protocolType == "tuic"
	
	isTransportLayerSecurityRequired := isProtocolRequiringImplicitTls || 
		securityFieldValue == "tls" || securityFieldValue == "reality" || 
		tlsEnabledParameter == "1" || tlsEnabledParameter == "true"
	
	if !isTransportLayerSecurityRequired {
		return nil
	}

	tlsConfig := &TransportLayerSecurityConfiguration{
		Enabled: true,
		ServerNameIndication: uriQueryParameters.Get("sni"),
	}
	
	if tlsConfig.ServerNameIndication == "" {
		tlsConfig.ServerNameIndication = uriQueryParameters.Get("peer")
	}
	
	if uriQueryParameters.Get("allowInsecure") == "1" || uriQueryParameters.Get("insecure") == "1" {
		tlsConfig.AllowInsecure = true
	}
	
	if alpnString := uriQueryParameters.Get("alpn"); alpnString != "" {
		tlsConfig.NextProtocolsNegotiation = strings.Split(alpnString, ",")
	}
	
	clientFingerprintIdentifier := uriQueryParameters.Get("fp")
	if clientFingerprintIdentifier == "" {
		clientFingerprintIdentifier = uriQueryParameters.Get("browser")
	}
	
	if clientFingerprintIdentifier != "" {
		tlsConfig.UTLSFingerprint = &UserAgentTlsFingerprintConfiguration{
			Enabled:     true,
			Fingerprint: clientFingerprintIdentifier,
		}
	}

	if securityFieldValue == "reality" {
		tlsConfig.RealitySecurity = &RealitySecurityProtocolConfiguration{
			Enabled:         true,
			PublicKeyBase64: uriQueryParameters.Get("pbk"),
			ShortIdHex:      uriQueryParameters.Get("sid"),
		}
		// Reality 模式通常需要强制开启 uTLS
		if tlsConfig.UTLSFingerprint == nil {
			tlsConfig.UTLSFingerprint = &UserAgentTlsFingerprintConfiguration{
				Enabled:     true,
				Fingerprint: "chrome",
			}
		}
	}
	return tlsConfig
}

func determineTransportConfigurationFromUriParameters(uriQueryParameters url.Values) *V2RayTransportLayerConfiguration {
	networkModeIdentifier := uriQueryParameters.Get("net")
	if networkModeIdentifier == "" {
		networkModeIdentifier = uriQueryParameters.Get("type")
	}
	
	if networkModeIdentifier == "" || networkModeIdentifier == "tcp" {
		return nil
	}

	transportConfig := &V2RayTransportLayerConfiguration{Type: networkModeIdentifier}
	hostHeaderValue := uriQueryParameters.Get("host")

	switch networkModeIdentifier {
	case "ws":
		transportConfig.Path = uriQueryParameters.Get("path")
		if transportConfig.Path == "" { transportConfig.Path = "/" }
		if hostHeaderValue != "" {
			transportConfig.Headers = map[string]string{"Host": hostHeaderValue}
		}
		if earlyDataValue := uriQueryParameters.Get("ed"); earlyDataValue != "" {
			transportConfig.MaxEarlyData = SafeConvertInterfaceToInteger(earlyDataValue)
			transportConfig.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		}
		// 兼容 http-upgrade 变体
		if uriQueryParameters.Get("v2ray-http-upgrade") == "true" || uriQueryParameters.Get("v2ray-http-upgrade") == "1" {
			transportConfig.Type = "httpupgrade"
			if hostHeaderValue != "" {
				transportConfig.Host = []string{hostHeaderValue}
			}
		}
	case "grpc":
		transportConfig.ServiceName = uriQueryParameters.Get("serviceName")
		if transportConfig.ServiceName == "" {
			transportConfig.ServiceName = uriQueryParameters.Get("path")
		}
	case "httpupgrade", "http", "h2":
		transportConfig.Path = uriQueryParameters.Get("path")
		if hostHeaderValue != "" {
			transportConfig.Host = strings.Split(hostHeaderValue, ",")
		}
	}
	return transportConfig
}

func convertVMessUriIntoSingBoxOutbound(rawUri string) (*StandardSingBoxOutboundConfiguration, error) {
	base64Payload := strings.TrimPrefix(rawUri, "vmess://")
	decodedJsonString, decodingError := AttemptRobustBase64DecodingOfSubscriptionContent(base64Payload)
	if decodingError != nil {
		return nil, decodingError
	}

	var legacyJsonData RawVMessJsonLegacyFormat
	// 尝试解析 V2RayN 风格的旧版 JSON 格式
	if json.Unmarshal([]byte(decodedJsonString), &legacyJsonData) == nil && legacyJsonData.Address != "" {
		outbound := &StandardSingBoxOutboundConfiguration{
			Type: "vmess",
			Tag: legacyJsonData.DisplayName,
			ServerAddress: legacyJsonData.Address,
			ServerPort: SafeConvertInterfaceToInteger(legacyJsonData.Port),
			UUID: legacyJsonData.ID,
			SecurityLayer: legacyJsonData.Security,
			VmessAlterId: SafeConvertInterfaceToInteger(legacyJsonData.AlterId),
			PacketEncodingType: "xudp",
		}
		
		if outbound.SecurityLayer == "" { outbound.SecurityLayer = "auto" }
		
		if legacyJsonData.TlsEnabled == "tls" {
			outbound.TLS = &TransportLayerSecurityConfiguration{
				Enabled: true,
				ServerNameIndication: legacyJsonData.Sni,
			}
			if outbound.TLS.ServerNameIndication == "" {
				outbound.TLS.ServerNameIndication = legacyJsonData.Host
			}
		}
		
		if legacyJsonData.Network != "" && legacyJsonData.Network != "tcp" {
			outbound.Transport = &V2RayTransportLayerConfiguration{
				Type: legacyJsonData.Network,
				Path: legacyJsonData.Path,
			}
			if legacyJsonData.Host != "" && (legacyJsonData.Network == "ws" || legacyJsonData.Network == "httpupgrade") {
				outbound.Transport.Headers = map[string]string{"Host": legacyJsonData.Host}
			}
		}
		return outbound, nil
	}
	
	// 如果不是旧版 JSON，则尝试按通用 Query-Style URI 解析
	return extractOutboundConfigurationFromQueryStyleUri("vmess", decodedJsonString)
}

func extractOutboundConfigurationFromQueryStyleUri(protocolScheme, rawUri string) (*StandardSingBoxOutboundConfiguration, error) {
	if !strings.Contains(rawUri, "://") {
		rawUri = protocolScheme + "://" + rawUri
	}
	
	parsedUrlObject, parsingError := url.Parse(rawUri)
	if parsingError != nil { return nil, parsingError }

	uriQueryParameters := parsedUrlObject.Query()
	decodedNodeDisplayNameTag, _ := url.QueryUnescape(parsedUrlObject.Fragment)
	if decodedNodeDisplayNameTag == "" {
		decodedNodeDisplayNameTag = parsedUrlObject.Hostname() + ":" + parsedUrlObject.Port()
	}

	outbound := &StandardSingBoxOutboundConfiguration{
		Type: protocolScheme,
		Tag: decodedNodeDisplayNameTag,
		ServerAddress: parsedUrlObject.Hostname(),
		ServerPort: SafeConvertInterfaceToInteger(parsedUrlObject.Port()),
	}

	rawUserInfoString := parsedUrlObject.User.String()
	// 特殊处理 Shadowsocks (SS) 的 Base64 用户信息
	if protocolScheme == "ss" && !strings.Contains(rawUserInfoString, ":") {
		if decodedUserInfo, err := AttemptRobustBase64DecodingOfSubscriptionContent(rawUserInfoString); err == nil {
			rawUserInfoString = decodedUserInfo
		}
	}

	// 提取密码、UUID 或 加密方法
	if strings.Contains(rawUserInfoString, ":") {
		userInfoParts := strings.SplitN(rawUserInfoString, ":", 2)
		if protocolScheme == "ss" {
			outbound.EncryptionMethod, outbound.Password = userInfoParts[0], userInfoParts[1]
		} else if protocolScheme == "trojan" {
			outbound.Password = userInfoParts[0]
		} else {
			outbound.UUID = userInfoParts[0]
		}
	} else {
		if protocolScheme == "trojan" || protocolScheme == "ss" {
			outbound.Password = rawUserInfoString
		} else {
			outbound.UUID = rawUserInfoString
		}
	}

	outbound.TLS = constructTlsConfigurationFromUriParameters(protocolScheme, uriQueryParameters)
	outbound.Transport = determineTransportConfigurationFromUriParameters(uriQueryParameters)

	// 根据不同协议补全特定字段
	switch protocolScheme {
	case "vless":
		outbound.FlowControl = uriQueryParameters.Get("flow")
		outbound.PacketEncodingType = "xudp"
	case "vmess":
		outbound.PacketEncodingType = "xudp"
		if outbound.SecurityLayer == "" { outbound.SecurityLayer = "auto" }
	case "hysteria2", "hy2":
		outbound.Type = "hysteria2"
		outbound.Password = rawUserInfoString
		outbound.UploadBandwidthMbps = SafeConvertInterfaceToInteger(uriQueryParameters.Get("upmbps"))
		outbound.DownloadBandwidthMbps = SafeConvertInterfaceToInteger(uriQueryParameters.Get("downmbps"))
		
		if obfsMode := uriQueryParameters.Get("obfs"); obfsMode != "" && obfsMode != "none" {
			outbound.Obfuscation = &Hysteria2ObfuscationConfiguration{
				Type:     "salamander",
				Password: uriQueryParameters.Get("obfs-password"),
			}
		}
	}
	return outbound, nil
}

func protocolSchemeIsHysteriaVariant(scheme string) bool {
	return scheme == "hysteria" || scheme == "hy"
}
