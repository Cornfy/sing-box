package subtool

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// StandardSingBoxOutboundConfiguration 定义当前转换器支持的 sing-box 出站配置字段。
type StandardSingBoxOutboundConfiguration struct {
	Type                     string                               `json:"type"`
	Tag                      string                               `json:"tag"`
	ServerAddress            string                               `json:"server,omitempty"`
	ServerPort               int                                  `json:"server_port,omitempty"`
	EncryptionMethod         string                               `json:"method,omitempty"`
	Password                 string                               `json:"password,omitempty"`
	UUID                     string                               `json:"uuid,omitempty"`
	SecurityLayer            string                               `json:"security,omitempty"`
	VmessAlterId             int                                  `json:"alter_id,omitempty"`
	FlowControl              string                               `json:"flow,omitempty"`
	PacketEncodingType       *string                              `json:"packet_encoding,omitempty"`
	TLS                      *TransportLayerSecurityConfiguration `json:"tls,omitempty"`
	Transport                *V2RayTransportLayerConfiguration    `json:"transport,omitempty"`
	Obfuscation              *Hysteria2ObfuscationConfiguration   `json:"obfs,omitempty"`
	UploadBandwidthMbps      int                                  `json:"up_mbps,omitempty"`
	DownloadBandwidthMbps    int                                  `json:"down_mbps,omitempty"`
	CongestionControl        string                               `json:"congestion_control,omitempty"`
	UDPRelayMode             string                               `json:"udp_relay_mode,omitempty"`
	UDPOverStream            bool                                 `json:"udp_over_stream,omitempty"`
	ZeroRTTHandshake         bool                                 `json:"zero_rtt_handshake,omitempty"`
	Heartbeat                string                               `json:"heartbeat,omitempty"`
	ServerPorts              []string                             `json:"server_ports,omitempty"`
	HopInterval              string                               `json:"hop_interval,omitempty"`
	Plugin                   string                               `json:"plugin,omitempty"`
	PluginOptions            string                               `json:"plugin_opts,omitempty"`
	IdleSessionCheckInterval string                               `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string                               `json:"idle_session_timeout,omitempty"`
	MinIdleSession           *int                                 `json:"min_idle_session,omitempty"`

	// 以下字段通常用于 sing-box 的动态分组 (urltest/selector)
	ConnectivityTestUrl string      `json:"url,omitempty"`
	TestInterval        string      `json:"interval,omitempty"`
	ToleranceValue      interface{} `json:"tolerance,omitempty"`
	Outbounds           []string    `json:"outbounds,omitempty"`
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
	Host                any               `json:"host,omitempty"`
}

type Hysteria2ObfuscationConfiguration struct {
	Type     string `json:"type"`
	Password string `json:"password,omitempty"`
}

// RawVMessJsonLegacyFormat 对应旧版 VMess 订阅中常见的 JSON 导入格式
type RawVMessJsonLegacyFormat struct {
	Address        string      `json:"add"`
	Port           interface{} `json:"port"`
	ID             string      `json:"id"`
	AlterId        interface{} `json:"aid"`
	Security       string      `json:"scy"`
	Network        string      `json:"net"`
	HeaderType     string      `json:"type"`
	Host           string      `json:"host"`
	Path           string      `json:"path"`
	TlsEnabled     string      `json:"tls"`
	Sni            string      `json:"sni"`
	DisplayName    string      `json:"ps"`
	ALPN           string      `json:"alpn"`
	Fingerprint    string      `json:"fp"`
	ServiceName    string      `json:"serviceName"`
	PacketEncoding *string     `json:"packetEncoding"`
	AllowInsecure  any         `json:"allowInsecure"`
}

// AttemptRobustBase64DecodingOfSubscriptionContent 兼容标准 Base64 及 URL 安全变体的解码器
func AttemptRobustBase64DecodingOfSubscriptionContent(rawBase64Input string) (string, error) {
	sanitizedBase64 := strings.Join(strings.Fields(strings.TrimPrefix(rawBase64Input, "\ufeff")), "")
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
	rawUri = strings.TrimSpace(strings.TrimPrefix(rawUri, "\ufeff"))
	if strings.HasPrefix(rawUri, "vmess://") {
		return convertVMessUriIntoSingBoxOutbound(rawUri)
	}

	if strings.HasPrefix(rawUri, "hysteria://") || strings.HasPrefix(rawUri, "hy://") {
		return nil, ErrUnsupportedHysteriaVersion1ShareLink
	}
	supportedProtocolSchemes := []string{"vless", "trojan", "ss", "hysteria2", "hy2", "tuic", "anytls"}
	for _, schemePrefix := range supportedProtocolSchemes {
		if strings.HasPrefix(rawUri, schemePrefix+"://") {
			return extractOutboundConfigurationFromQueryStyleUri(schemePrefix, rawUri)
		}
	}
	return nil, fmt.Errorf("不支持的协议方案或无效的 URI")
}

// extractFirstNonEmptyValueFromUriParameterAliases 按别名顺序提取首个非空参数值，优先保留标准参数。
func extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters url.Values, parameterAliasNames ...string) string {
	for _, parameterAliasName := range parameterAliasNames {
		if parameterValue := uriQueryParameters.Get(parameterAliasName); parameterValue != "" {
			return parameterValue
		}
	}
	return ""
}

var ErrInvalidRealityPublicKey = errors.New("Reality public key must be a 32-byte unpadded URL-safe Base64 value")
var ErrInvalidRealityShortId = errors.New("Reality short ID must contain an even number of hexadecimal digits (at most 16)")
var ErrUnsupportedHysteriaVersion1ShareLink = errors.New("Hysteria v1 share links are not supported")
var ErrUnsupportedProtocolOption = errors.New("unsupported protocol option")

// DetermineSubscriptionRecordFailureCategoryFromConversionError 返回固定错误分类，不包含 URI 或错误中的私密值。
func DetermineSubscriptionRecordFailureCategoryFromConversionError(rawUri string, conversionError error) string {
	switch {
	case errors.Is(conversionError, ErrInvalidRealityPublicKey):
		return "Reality 公钥缺失或格式无效"
	case errors.Is(conversionError, ErrInvalidRealityShortId):
		return "Reality Short ID 格式无效"
	case errors.Is(conversionError, ErrUnsupportedHysteriaVersion1ShareLink):
		return "当前转换器不支持 Hysteria v1 分享链接"
	case errors.Is(conversionError, ErrUnsupportedProtocolOption):
		return "节点包含当前转换器不支持的参数或模式"
	}
	for _, protocolScheme := range []string{"vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "hysteria", "tuic", "anytls"} {
		if strings.HasPrefix(rawUri, protocolScheme+"://") {
			return "已支持协议的 URI 或编码无效"
		}
	}
	// 仅允许预定义的协议名称出现在错误分类中，避免输出私密内容。
	for _, protocolScheme := range []string{"ssr", "naive+https", "naive+http", "shadowtls", "wireguard", "socks", "socks5", "hy"} {
		if strings.HasPrefix(strings.ToLower(rawUri), protocolScheme+"://") {
			return "当前转换器不支持的协议: " + protocolScheme
		}
	}
	if strings.HasPrefix(rawUri, "http://") || strings.HasPrefix(rawUri, "https://") {
		return "HTTP/HTTPS 链接（未作为节点解析）"
	}
	for _, protocolScheme := range []string{"vmess", "vless", "trojan", "ss", "hysteria2", "hy2", "hysteria", "tuic", "anytls"} {
		if strings.HasPrefix(strings.ToLower(rawUri), protocolScheme+"://") {
			return "已支持协议的名称大小写不兼容"
		}
	}
	if strings.Contains(rawUri, "://") {
		return "不支持的协议或链接"
	}
	return "非节点内容或无法识别的格式"
}

// validateRealitySecurityProtocolConfiguration 校验 Reality 公钥与 Short ID 的格式。
func validateRealitySecurityProtocolConfiguration(tlsConfiguration *TransportLayerSecurityConfiguration) error {
	if tlsConfiguration == nil || tlsConfiguration.RealitySecurity == nil {
		return nil
	}
	realitySecurityConfiguration := tlsConfiguration.RealitySecurity
	decodedPublicKeyBytes, decodingError := base64.RawURLEncoding.DecodeString(realitySecurityConfiguration.PublicKeyBase64)
	if decodingError != nil || len(decodedPublicKeyBytes) != 32 {
		return ErrInvalidRealityPublicKey
	}
	decodedShortIdBytes, decodingError := hex.DecodeString(realitySecurityConfiguration.ShortIdHex)
	if decodingError != nil || len(decodedShortIdBytes) > 8 {
		return ErrInvalidRealityShortId
	}
	return nil
}

// checkIfAnyUriParameterAliasIsEnabled 检查指定别名中是否存在已启用的布尔参数。
func checkIfAnyUriParameterAliasIsEnabled(uriQueryParameters url.Values, parameterAliasNames ...string) bool {
	for _, parameterAliasName := range parameterAliasNames {
		isParameterEnabled, booleanParsingError := strconv.ParseBool(uriQueryParameters.Get(parameterAliasName))
		if booleanParsingError == nil && isParameterEnabled {
			return true
		}
	}
	return false
}

func constructTlsConfigurationFromUriParameters(protocolType string, uriQueryParameters url.Values) *TransportLayerSecurityConfiguration {
	securityFieldValue := strings.ToLower(uriQueryParameters.Get("security"))
	tlsEnabledParameter := strings.ToLower(uriQueryParameters.Get("tls"))

	// 某些协议默认隐含了 TLS
	isProtocolRequiringImplicitTls := protocolType == "trojan" || protocolType == "hysteria2" ||
		protocolType == "hy2" || protocolType == "tuic" || protocolType == "anytls"

	isTransportLayerSecurityRequired := isProtocolRequiringImplicitTls ||
		securityFieldValue == "tls" || securityFieldValue == "reality" ||
		tlsEnabledParameter == "1" || tlsEnabledParameter == "true" || tlsEnabledParameter == "tls"

	if !isTransportLayerSecurityRequired {
		return nil
	}

	tlsConfig := &TransportLayerSecurityConfiguration{
		Enabled:              true,
		ServerNameIndication: extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "sni", "serverName", "server_name"),
	}

	if tlsConfig.ServerNameIndication == "" {
		tlsConfig.ServerNameIndication = uriQueryParameters.Get("peer")
	}

	if checkIfAnyUriParameterAliasIsEnabled(uriQueryParameters, "allowInsecure", "insecure", "allow_insecure", "skip-cert-verify") {
		tlsConfig.AllowInsecure = true
	}

	if alpnString := uriQueryParameters.Get("alpn"); alpnString != "" {
		tlsConfig.NextProtocolsNegotiation = strings.Split(alpnString, ",")
	}

	clientFingerprintIdentifier := extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "fp", "fingerprint")
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
			PublicKeyBase64: extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "pbk", "publicKey", "public_key"),
			ShortIdHex:      extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "sid", "shortId", "short_id"),
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

func determineTransportConfigurationFromUriParameters(uriQueryParameters url.Values) (*V2RayTransportLayerConfiguration, error) {
	networkModeIdentifier := extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "net", "type")
	if networkModeIdentifier == "" || networkModeIdentifier == "tcp" {
		if tcpHeaderType := uriQueryParameters.Get("headerType"); tcpHeaderType != "" && tcpHeaderType != "none" {
			return nil, ErrUnsupportedProtocolOption
		}
		return nil, nil
	}
	if networkModeIdentifier == "h2" {
		networkModeIdentifier = "http"
	}
	if networkModeIdentifier == "ws" && checkIfAnyUriParameterAliasIsEnabled(uriQueryParameters, "v2ray-http-upgrade") {
		networkModeIdentifier = "httpupgrade"
	}
	transportConfiguration := &V2RayTransportLayerConfiguration{Type: networkModeIdentifier}
	hostHeaderValue := uriQueryParameters.Get("host")
	switch networkModeIdentifier {
	case "ws":
		transportConfiguration.Path = uriQueryParameters.Get("path")
		if transportConfiguration.Path == "" {
			transportConfiguration.Path = "/"
		}
		if hostHeaderValue != "" {
			transportConfiguration.Headers = map[string]string{"Host": hostHeaderValue}
		}
		if earlyDataParameterValue := uriQueryParameters.Get("ed"); earlyDataParameterValue != "" {
			earlyDataSizeInBytes, integerParsingError := strconv.Atoi(earlyDataParameterValue)
			if integerParsingError != nil || earlyDataSizeInBytes < 0 || uint64(earlyDataSizeInBytes) > 1<<32-1 {
				return nil, errors.New("invalid WebSocket early data size")
			}
			transportConfiguration.MaxEarlyData = earlyDataSizeInBytes
			transportConfiguration.EarlyDataHeaderName = extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "eh", "early_data_header_name")
			if transportConfiguration.EarlyDataHeaderName == "" {
				transportConfiguration.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			}
		}
	case "grpc":
		if grpcStreamMode := uriQueryParameters.Get("mode"); grpcStreamMode != "" && grpcStreamMode != "gun" {
			return nil, ErrUnsupportedProtocolOption
		}
		transportConfiguration.ServiceName = extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "serviceName", "service_name", "path")
	case "httpupgrade":
		transportConfiguration.Path = uriQueryParameters.Get("path")
		if hostHeaderValue != "" {
			transportConfiguration.Host = hostHeaderValue
		}
	case "http":
		transportConfiguration.Path = uriQueryParameters.Get("path")
		if hostHeaderValue != "" {
			transportConfiguration.Host = strings.Split(hostHeaderValue, ",")
		}
	case "quic":
		if uriQueryParameters.Get("quicSecurity") != "" && uriQueryParameters.Get("quicSecurity") != "none" || uriQueryParameters.Get("key") != "" {
			return nil, ErrUnsupportedProtocolOption
		}
	default:
		return nil, ErrUnsupportedProtocolOption
	}
	return transportConfiguration, nil
}

func convertVMessUriIntoSingBoxOutbound(rawUri string) (*StandardSingBoxOutboundConfiguration, error) {
	base64Payload := strings.TrimPrefix(rawUri, "vmess://")
	// Query 风格的 VMess 分享链接可以直接解析，无需包裹 Base64。
	if strings.Contains(base64Payload, "@") {
		return extractOutboundConfigurationFromQueryStyleUri("vmess", rawUri)
	}
	decodedJsonString, conversionError := AttemptRobustBase64DecodingOfSubscriptionContent(base64Payload)
	if conversionError != nil {
		return nil, errors.New("invalid VMess Base64 payload")
	}
	if !strings.HasPrefix(strings.TrimSpace(decodedJsonString), "{") {
		return extractOutboundConfigurationFromQueryStyleUri("vmess", decodedJsonString)
	}
	var legacyJsonData RawVMessJsonLegacyFormat
	if json.Unmarshal([]byte(decodedJsonString), &legacyJsonData) != nil {
		return nil, errors.New("invalid VMess JSON payload")
	}
	uriQueryParameters := url.Values{"net": {legacyJsonData.Network}, "path": {legacyJsonData.Path}, "host": {legacyJsonData.Host},
		"sni": {legacyJsonData.Sni}, "tls": {legacyJsonData.TlsEnabled}, "scy": {legacyJsonData.Security},
		"alpn": {legacyJsonData.ALPN}, "fp": {legacyJsonData.Fingerprint}, "serviceName": {legacyJsonData.ServiceName}}
	if legacyJsonData.PacketEncoding != nil {
		uriQueryParameters.Set("packetEncoding", *legacyJsonData.PacketEncoding)
	}
	if legacyJsonData.AllowInsecure != nil {
		uriQueryParameters.Set("allowInsecure", fmt.Sprint(legacyJsonData.AllowInsecure))
	}
	if legacyJsonData.Network == "tcp" || legacyJsonData.Network == "" {
		uriQueryParameters.Set("headerType", legacyJsonData.HeaderType)
	}
	if legacyJsonData.Network == "quic" {
		uriQueryParameters.Set("quicSecurity", legacyJsonData.Host)
		uriQueryParameters.Set("key", legacyJsonData.Path)
	}
	// 将 JSON 字段组装为 URI，复用统一的认证、TLS 和传输配置映射。
	serverAddressString := legacyJsonData.Address
	if strings.Contains(serverAddressString, ":") && !strings.HasPrefix(serverAddressString, "[") {
		serverAddressString = "[" + serverAddressString + "]"
	}
	parsedUrlObject := &url.URL{Scheme: "vmess", User: url.User(legacyJsonData.ID), Host: serverAddressString + ":" + fmt.Sprint(legacyJsonData.Port), RawQuery: uriQueryParameters.Encode(), Fragment: legacyJsonData.DisplayName}
	outboundConfiguration, conversionError := extractOutboundConfigurationFromQueryStyleUri("vmess", parsedUrlObject.String())
	if conversionError != nil {
		return nil, conversionError
	}
	// 兼容旧版订阅：未指定 SNI 时，将单个 Host 值作为回退。
	if outboundConfiguration.TLS != nil && outboundConfiguration.TLS.ServerNameIndication == "" && !strings.Contains(legacyJsonData.Host, ",") {
		outboundConfiguration.TLS.ServerNameIndication = legacyJsonData.Host
	}
	if legacyJsonData.AlterId != nil && fmt.Sprint(legacyJsonData.AlterId) != "" {
		outboundConfiguration.VmessAlterId, conversionError = strconv.Atoi(fmt.Sprint(legacyJsonData.AlterId))
		if conversionError != nil {
			return nil, errors.New("invalid VMess alter ID")
		}
	}
	if outboundConfiguration.VmessAlterId < 0 || outboundConfiguration.VmessAlterId > 65535 {
		return nil, errors.New("invalid VMess alter ID")
	}
	return outboundConfiguration, nil
}

func extractOutboundConfigurationFromQueryStyleUri(protocolScheme, rawUri string) (*StandardSingBoxOutboundConfiguration, error) {
	if !strings.Contains(rawUri, "://") {
		rawUri = protocolScheme + "://" + rawUri
	}
	var authorityServerPortRanges []string
	var conversionError error
	if protocolScheme == "ss" {
		rawUri, conversionError = normalizeLegacyShadowsocksShareUriPayload(rawUri)
	} else if protocolScheme == "hysteria2" || protocolScheme == "hy2" {
		rawUri, authorityServerPortRanges, conversionError = normalizeHysteria2UriAuthorityPortRanges(rawUri)
	}
	if conversionError != nil {
		return nil, conversionError
	}
	parsedUrlObject, conversionError := url.Parse(rawUri)
	if conversionError != nil {
		return nil, errors.New("invalid node URI")
	}
	if parsedUrlObject.Scheme != protocolScheme {
		return nil, errors.New("mismatched URI scheme")
	}
	uriQueryParameters, conversionError := url.ParseQuery(parsedUrlObject.RawQuery)
	if conversionError != nil {
		return nil, errors.New("invalid URI query encoding")
	}
	if conversionError = validateSupportedUriQueryParameterValues(uriQueryParameters); conversionError != nil {
		return nil, conversionError
	}
	if protocolScheme != "vmess" {
		switch strings.ToLower(uriQueryParameters.Get("security")) {
		case "", "none", "tls", "reality":
		default:
			return nil, ErrUnsupportedProtocolOption
		}
	}
	serverPortString := parsedUrlObject.Port()
	if serverPortString == "" && (protocolScheme == "hy2" || protocolScheme == "hysteria2") {
		serverPortString = "443"
	}
	serverPortNumber, conversionError := parseAndValidateServerPortNumber(serverPortString)
	if conversionError != nil {
		return nil, conversionError
	}
	if !checkIfServerAddressIsValid(parsedUrlObject.Hostname()) {
		return nil, errors.New("missing or invalid server address")
	}
	outboundConfiguration := &StandardSingBoxOutboundConfiguration{Type: protocolScheme, Tag: parsedUrlObject.Fragment, ServerAddress: parsedUrlObject.Hostname(), ServerPort: serverPortNumber}
	if outboundConfiguration.Tag == "" {
		outboundConfiguration.Tag = parsedUrlObject.Hostname() + ":" + serverPortString
	}
	if parsedUrlObject.User == nil {
		return nil, errors.New("missing node authentication")
	}
	decodedUserName := parsedUrlObject.User.Username()
	decodedPassword, hasPasswordComponent := parsedUrlObject.User.Password()
	switch protocolScheme {
	case "ss":
		outboundConfiguration.Type = "shadowsocks"
		if hasPasswordComponent {
			outboundConfiguration.EncryptionMethod, outboundConfiguration.Password = decodedUserName, decodedPassword
		} else {
			decodedUserInfo, conversionError := AttemptRobustBase64DecodingOfSubscriptionContent(decodedUserName)
			if conversionError != nil {
				return nil, errors.New("invalid Shadowsocks user info")
			}
			userInfoComponents := strings.SplitN(decodedUserInfo, ":", 2)
			if len(userInfoComponents) != 2 {
				return nil, errors.New("invalid Shadowsocks user info")
			}
			outboundConfiguration.EncryptionMethod, outboundConfiguration.Password = userInfoComponents[0], userInfoComponents[1]
		}
		if !checkIfShadowsocksEncryptionMethodIsSupported(outboundConfiguration.EncryptionMethod) {
			return nil, ErrUnsupportedProtocolOption
		}
		if outboundConfiguration.Password == "" && outboundConfiguration.EncryptionMethod != "none" {
			return nil, errors.New("missing Shadowsocks password")
		}
		if pluginParameterValue := uriQueryParameters.Get("plugin"); pluginParameterValue != "" {
			pluginParameterComponents := strings.SplitN(pluginParameterValue, ";", 2)
			outboundConfiguration.Plugin = pluginParameterComponents[0]
			if outboundConfiguration.Plugin == "simple-obfs" {
				outboundConfiguration.Plugin = "obfs-local"
			}
			if outboundConfiguration.Plugin != "obfs-local" && outboundConfiguration.Plugin != "v2ray-plugin" {
				return nil, ErrUnsupportedProtocolOption
			}
			if len(pluginParameterComponents) == 2 {
				outboundConfiguration.PluginOptions = pluginParameterComponents[1]
			}
		}
	case "trojan":
		if hasPasswordComponent {
			return nil, errors.New("Trojan requires password-only user info")
		}
		outboundConfiguration.Password = decodedUserName
	case "vless", "vmess":
		if hasPasswordComponent || !checkIfStringContainsValidUuid(decodedUserName) {
			return nil, errors.New("invalid UUID user info")
		}
		outboundConfiguration.UUID = decodedUserName
		packetEncodingType := "xudp"
		for _, parameterName := range []string{"packetEncoding", "packet_encoding"} {
			if parameterValues, ok := uriQueryParameters[parameterName]; ok {
				packetEncodingType = parameterValues[0]
				break
			}
		}
		if packetEncodingType != "" && packetEncodingType != "xudp" && packetEncodingType != "packetaddr" {
			return nil, ErrUnsupportedProtocolOption
		}
		outboundConfiguration.PacketEncodingType = &packetEncodingType
		if protocolScheme == "vless" {
			outboundConfiguration.FlowControl = uriQueryParameters.Get("flow")
			if outboundConfiguration.FlowControl != "" && outboundConfiguration.FlowControl != "xtls-rprx-vision" {
				return nil, ErrUnsupportedProtocolOption
			}
			if vlessEncryptionMode := uriQueryParameters.Get("encryption"); vlessEncryptionMode != "" && vlessEncryptionMode != "none" {
				return nil, ErrUnsupportedProtocolOption
			}
		} else {
			outboundConfiguration.SecurityLayer = extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "scy", "encryption")
			if outboundConfiguration.SecurityLayer == "" {
				switch uriQueryParameters.Get("security") {
				case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
					outboundConfiguration.SecurityLayer = uriQueryParameters.Get("security")
				}
			}
			if outboundConfiguration.SecurityLayer == "" {
				outboundConfiguration.SecurityLayer = "auto"
			}
			switch outboundConfiguration.SecurityLayer {
			case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305":
			default:
				return nil, ErrUnsupportedProtocolOption
			}
		}
	case "tuic":
		if !hasPasswordComponent || !checkIfStringContainsValidUuid(decodedUserName) || decodedPassword == "" {
			return nil, errors.New("TUIC requires UUID and password user info")
		}
		outboundConfiguration.UUID, outboundConfiguration.Password = decodedUserName, decodedPassword
		outboundConfiguration.CongestionControl = uriQueryParameters.Get("congestion_control")
		switch outboundConfiguration.CongestionControl {
		case "", "cubic", "new_reno", "bbr":
		default:
			return nil, ErrUnsupportedProtocolOption
		}
		outboundConfiguration.UDPRelayMode = uriQueryParameters.Get("udp_relay_mode")
		switch outboundConfiguration.UDPRelayMode {
		case "", "native", "quic":
		default:
			return nil, ErrUnsupportedProtocolOption
		}
		outboundConfiguration.UDPOverStream = checkIfAnyUriParameterAliasIsEnabled(uriQueryParameters, "udp_over_stream")
		if outboundConfiguration.UDPOverStream && outboundConfiguration.UDPRelayMode != "" {
			return nil, errors.New("TUIC UDP over stream conflicts with UDP relay mode")
		}
		outboundConfiguration.ZeroRTTHandshake = checkIfAnyUriParameterAliasIsEnabled(uriQueryParameters, "zero_rtt_handshake")
		outboundConfiguration.Heartbeat = uriQueryParameters.Get("heartbeat")
		if conversionError = validatePositiveTimeDurationString(outboundConfiguration.Heartbeat); conversionError != nil {
			return nil, conversionError
		}
	case "anytls":
		if hasPasswordComponent {
			return nil, errors.New("AnyTLS requires password-only user info")
		}
		outboundConfiguration.Password = decodedUserName
		outboundConfiguration.IdleSessionCheckInterval = uriQueryParameters.Get("idle_session_check_interval")
		outboundConfiguration.IdleSessionTimeout = uriQueryParameters.Get("idle_session_timeout")
		if conversionError = validatePositiveTimeDurationString(outboundConfiguration.IdleSessionCheckInterval); conversionError != nil {
			return nil, conversionError
		}
		if conversionError = validatePositiveTimeDurationString(outboundConfiguration.IdleSessionTimeout); conversionError != nil {
			return nil, conversionError
		}
		if numericParameterConfiguration, ok := uriQueryParameters["min_idle_session"]; ok {
			minimumIdleSessionCount, conversionError := strconv.Atoi(numericParameterConfiguration[0])
			if conversionError != nil || minimumIdleSessionCount < 0 {
				return nil, errors.New("invalid AnyTLS idle session count")
			}
			outboundConfiguration.MinIdleSession = &minimumIdleSessionCount
		}
	case "hysteria2", "hy2":
		outboundConfiguration.Type = "hysteria2"
		outboundConfiguration.Password = decodedUserName
		if hasPasswordComponent {
			outboundConfiguration.Password += ":" + decodedPassword
		}
		outboundConfiguration.ServerPorts = authorityServerPortRanges
		if serverPortRangeSpecification := extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "mport", "ports", "server_ports"); serverPortRangeSpecification != "" {
			if len(authorityServerPortRanges) != 0 {
				return nil, errors.New("conflicting Hysteria2 port lists")
			}
			outboundConfiguration.ServerPorts, conversionError = parseAndNormalizeServerPortRangeList(serverPortRangeSpecification)
			if conversionError != nil {
				return nil, conversionError
			}
		}
		if len(outboundConfiguration.ServerPorts) != 0 {
			outboundConfiguration.ServerPort = 0
		}
		outboundConfiguration.HopInterval = extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "hop_interval", "hopInterval")
		if outboundConfiguration.HopInterval != "" {
			if _, conversionError := strconv.Atoi(outboundConfiguration.HopInterval); conversionError == nil {
				outboundConfiguration.HopInterval += "s"
			}
			if len(outboundConfiguration.ServerPorts) == 0 {
				return nil, errors.New("Hysteria2 hop interval requires a port list")
			}
			if conversionError = validatePositiveTimeDurationString(outboundConfiguration.HopInterval); conversionError != nil {
				return nil, conversionError
			}
		}
		for _, numericParameterConfiguration := range []struct {
			names       []string
			destination *int
		}{
			{[]string{"upmbps", "up_mbps"}, &outboundConfiguration.UploadBandwidthMbps},
			{[]string{"downmbps", "down_mbps"}, &outboundConfiguration.DownloadBandwidthMbps},
		} {
			if numericParameterValue := extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, numericParameterConfiguration.names...); numericParameterValue != "" {
				parsedNumericValue, conversionError := strconv.Atoi(numericParameterValue)
				if conversionError != nil || parsedNumericValue <= 0 {
					return nil, errors.New("invalid Hysteria2 bandwidth")
				}
				*numericParameterConfiguration.destination = parsedNumericValue
			}
		}
		switch uriQueryParameters.Get("obfs") {
		case "", "none":
			if uriQueryParameters.Get("obfs-password") != "" {
				return nil, errors.New("obfuscation password without obfuscation")
			}
		case "salamander":
			if uriQueryParameters.Get("obfs-password") == "" {
				return nil, errors.New("missing Salamander password")
			}
			outboundConfiguration.Obfuscation = &Hysteria2ObfuscationConfiguration{Type: "salamander", Password: uriQueryParameters.Get("obfs-password")}
		default:
			return nil, ErrUnsupportedProtocolOption
		}
	}
	if outboundConfiguration.Password == "" && outboundConfiguration.UUID == "" && outboundConfiguration.EncryptionMethod != "none" {
		return nil, errors.New("missing node authentication")
	}
	outboundConfiguration.TLS = constructTlsConfigurationFromUriParameters(protocolScheme, uriQueryParameters)
	if conversionError = validateRealitySecurityProtocolConfiguration(outboundConfiguration.TLS); conversionError != nil {
		return nil, conversionError
	}
	if outboundConfiguration.TLS != nil && outboundConfiguration.TLS.RealitySecurity != nil && protocolScheme != "vless" && protocolScheme != "trojan" {
		return nil, ErrUnsupportedProtocolOption
	}
	if protocolScheme == "vless" || protocolScheme == "vmess" || protocolScheme == "trojan" {
		outboundConfiguration.Transport, conversionError = determineTransportConfigurationFromUriParameters(uriQueryParameters)
		if conversionError != nil {
			return nil, conversionError
		}
		if outboundConfiguration.FlowControl != "" && (outboundConfiguration.Transport != nil || outboundConfiguration.TLS == nil) {
			return nil, errors.New("Vision requires TLS and TCP transport")
		}
	} else if extractFirstNonEmptyValueFromUriParameterAliases(uriQueryParameters, "net", "type") != "" {
		return nil, ErrUnsupportedProtocolOption
	}
	if protocolScheme == "ss" && outboundConfiguration.TLS != nil {
		return nil, ErrUnsupportedProtocolOption
	}
	return outboundConfiguration, nil
}

// checkIfStringContainsValidUuid 检查字符串是否为可接受的 UUID 格式。
func checkIfStringContainsValidUuid(uuidString string) bool {
	if len(uuidString) == 36 {
		for _, hyphenPosition := range []int{8, 13, 18, 23} {
			if uuidString[hyphenPosition] != '-' {
				return false
			}
		}
		uuidString = strings.ReplaceAll(uuidString, "-", "")
	}
	if len(uuidString) != 32 {
		return false
	}
	_, hexDecodingError := hex.DecodeString(uuidString)
	return hexDecodingError == nil
}

// checkIfServerAddressIsValid 检查服务器地址是否为空或包含非法字符。
func checkIfServerAddressIsValid(serverAddress string) bool {
	return serverAddress != "" && !strings.ContainsAny(serverAddress, " /\\?#@\t\r\n") &&
		(!strings.Contains(serverAddress, ":") || net.ParseIP(serverAddress) != nil)
}

// parseAndValidateServerPortNumber 解析端口并校验其是否位于有效范围内。
func parseAndValidateServerPortNumber(serverPortString string) (int, error) {
	for _, portCharacter := range serverPortString {
		if portCharacter < '0' || portCharacter > '9' {
			return 0, errors.New("invalid server port")
		}
	}
	serverPortNumber, integerParsingError := strconv.Atoi(serverPortString)
	if integerParsingError != nil || serverPortNumber < 1 || serverPortNumber > 65535 {
		return 0, errors.New("missing or invalid server port")
	}
	return serverPortNumber, nil
}

// validatePositiveTimeDurationString 校验非空时长是否为有效的正值。
func validatePositiveTimeDurationString(timeDurationString string) error {
	if timeDurationString == "" {
		return nil
	}
	parsedTimeDuration, durationParsingError := time.ParseDuration(timeDurationString)
	if durationParsingError != nil || parsedTimeDuration <= 0 {
		return errors.New("invalid positive duration")
	}
	return nil
}

// validateSupportedUriQueryParameterValues 校验已支持的查询参数并拒绝无法映射的关键选项。
func validateSupportedUriQueryParameterValues(uriQueryParameters url.Values) error {
	// 明确拒绝无法映射的安全与连接参数，避免静默忽略后改变节点行为。
	for _, parameterName := range []string{"pinSHA256", "ech"} {
		if uriQueryParameters.Get(parameterName) != "" {
			return ErrUnsupportedProtocolOption
		}
	}
	for _, parameterName := range []string{"allowInsecure", "insecure", "allow_insecure", "skip-cert-verify", "udp_over_stream", "zero_rtt_handshake", "v2ray-http-upgrade"} {
		if parameterValues, ok := uriQueryParameters[parameterName]; ok {
			if _, booleanParsingError := strconv.ParseBool(parameterValues[0]); booleanParsingError != nil {
				return errors.New("invalid boolean option")
			}
		}
	}
	for _, parameterValues := range uriQueryParameters {
		if len(parameterValues) != 1 {
			return errors.New("duplicate query parameters")
		}
	}
	securityModeIdentifier := strings.ToLower(uriQueryParameters.Get("security"))
	switch securityModeIdentifier {
	case "", "none", "tls", "reality", "auto", "zero", "aes-128-gcm", "chacha20-poly1305":
	default:
		return ErrUnsupportedProtocolOption
	}
	tlsModeIdentifier := strings.ToLower(uriQueryParameters.Get("tls"))
	switch tlsModeIdentifier {
	case "", "tls", "none", "0", "1", "true", "false":
	default:
		return ErrUnsupportedProtocolOption
	}
	return nil
}

// parseAndNormalizeServerPortRangeList 将单端口与端口范围转换为 sing-box 使用的范围列表。
func parseAndNormalizeServerPortRangeList(serverPortRangeSpecification string) ([]string, error) {
	var normalizedServerPortRanges []string
	for _, portRangeComponent := range strings.Split(serverPortRangeSpecification, ",") {
		portRangeComponent = strings.TrimSpace(portRangeComponent)
		portRangeBoundaries := strings.Split(strings.ReplaceAll(portRangeComponent, "-", ":"), ":")
		if len(portRangeBoundaries) < 1 || len(portRangeBoundaries) > 2 {
			return nil, errors.New("invalid port list")
		}
		rangeStartPortNumber, portParsingError := parseAndValidateServerPortNumber(portRangeBoundaries[0])
		if portParsingError != nil {
			return nil, portParsingError
		}
		if len(portRangeBoundaries) == 1 {
			// sing-box 要求每项均使用端口范围格式，单端口也写成相同的起止端口。
			normalizedServerPortRanges = append(normalizedServerPortRanges, strconv.Itoa(rangeStartPortNumber)+":"+strconv.Itoa(rangeStartPortNumber))
			continue
		}
		rangeEndPortNumber, portParsingError := parseAndValidateServerPortNumber(portRangeBoundaries[1])
		if portParsingError != nil || rangeEndPortNumber < rangeStartPortNumber {
			return nil, errors.New("invalid port range")
		}
		normalizedServerPortRanges = append(normalizedServerPortRanges, strconv.Itoa(rangeStartPortNumber)+":"+strconv.Itoa(rangeEndPortNumber))
	}
	return normalizedServerPortRanges, nil
}

// normalizeHysteria2UriAuthorityPortRanges 提取 Hysteria2 地址中的端口范围，并生成可由标准 URL 库解析的 URI。
func normalizeHysteria2UriAuthorityPortRanges(rawUri string) (string, []string, error) {
	authorityStartIndex := strings.Index(rawUri, "://") + 3
	authorityEndIndex := len(rawUri)
	if authorityTerminatorIndex := strings.IndexAny(rawUri[authorityStartIndex:], "/?#"); authorityTerminatorIndex >= 0 {
		authorityEndIndex = authorityStartIndex + authorityTerminatorIndex
	}
	rawAuthorityString := rawUri[authorityStartIndex:authorityEndIndex]
	serverAddressStartIndex := strings.LastIndex(rawAuthorityString, "@") + 1
	serverAuthorityString := rawAuthorityString[serverAddressStartIndex:]
	portSeparatorIndex := strings.LastIndex(serverAuthorityString, ":")
	if strings.HasPrefix(serverAuthorityString, "[") {
		ipv6ClosingBracketIndex := strings.Index(serverAuthorityString, "]")
		if ipv6ClosingBracketIndex < 0 {
			return "", nil, errors.New("invalid IPv6 authority")
		}
		if portSeparatorIndex < ipv6ClosingBracketIndex {
			return rawUri, nil, nil
		}
	}
	if portSeparatorIndex < 0 {
		return rawUri, nil, nil
	}
	serverPortRangeSpecification := serverAuthorityString[portSeparatorIndex+1:]
	if !strings.ContainsAny(serverPortRangeSpecification, ",-:") {
		return rawUri, nil, nil
	}
	normalizedServerPortRanges, portParsingError := parseAndNormalizeServerPortRangeList(serverPortRangeSpecification)
	if portParsingError != nil {
		return "", nil, portParsingError
	}
	firstRangePortNumberString := strings.SplitN(normalizedServerPortRanges[0], ":", 2)[0]
	portSpecificationStartIndex := authorityStartIndex + serverAddressStartIndex + portSeparatorIndex + 1
	return rawUri[:portSpecificationStartIndex] + firstRangePortNumberString + rawUri[authorityEndIndex:], normalizedServerPortRanges, nil
}

// normalizeLegacyShadowsocksShareUriPayload 将旧版整段 Base64 编码的 SS 分享链接转换为 SIP002 格式。
func normalizeLegacyShadowsocksShareUriPayload(rawUri string) (string, error) {
	rawShareLinkPayload := strings.TrimPrefix(rawUri, "ss://")
	// 旧版 SS 分享链接会将整个 method:password@host:port 部分编码为 Base64。
	payloadEndIndex := strings.IndexAny(rawShareLinkPayload, "?#")
	if payloadEndIndex < 0 {
		payloadEndIndex = len(rawShareLinkPayload)
	}
	if strings.Contains(rawShareLinkPayload[:payloadEndIndex], "@") {
		return rawUri, nil
	}
	decodedAuthorityString, decodingError := AttemptRobustBase64DecodingOfSubscriptionContent(strings.TrimSuffix(rawShareLinkPayload[:payloadEndIndex], "/"))
	if decodingError != nil {
		return "", errors.New("invalid legacy Shadowsocks payload")
	}
	userInfoSeparatorIndex := strings.LastIndex(decodedAuthorityString, "@")
	if userInfoSeparatorIndex < 0 {
		return "", errors.New("missing Shadowsocks server")
	}
	credentialComponents := strings.SplitN(decodedAuthorityString[:userInfoSeparatorIndex], ":", 2)
	if len(credentialComponents) != 2 {
		return "", errors.New("invalid Shadowsocks credentials")
	}
	encodedUserInfoString := url.UserPassword(credentialComponents[0], credentialComponents[1]).String()
	return "ss://" + encodedUserInfoString + "@" + decodedAuthorityString[userInfoSeparatorIndex+1:] + rawShareLinkPayload[payloadEndIndex:], nil
}

// checkIfShadowsocksEncryptionMethodIsSupported 检查加密方法是否属于当前支持的 Shadowsocks 方法。
func checkIfShadowsocksEncryptionMethodIsSupported(encryptionMethodIdentifier string) bool {
	switch encryptionMethodIdentifier {
	case "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20":
		return true
	}
	return false
}
