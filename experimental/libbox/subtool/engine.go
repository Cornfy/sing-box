package subtool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/iancoleman/orderedmap"
)

// TemplateLogicControlConfiguration 定义了模板中 `_extra` 字段的结构
type TemplateLogicControlConfiguration struct {
	RemoteSubscriptionUrls [][]string `json:"sub_urls"`
	NodeFilterRegexPattern string     `json:"filter_keywords"`
	RegionalGroupConfigs   [][]string `json:"regions"`
}

type ScheduledSubscriptionFetchTask struct {
	SubscriptionLabel string
	SubscriptionUrl   string
}

// ProcessTemplateString 接收模板 JSON 字符串，执行拉取、过滤、分组、替换，返回最终 JSON 字符串
func ProcessTemplateString(templateContent string) (string, error) {
	if strings.TrimSpace(templateContent) == "" {
		return "", fmt.Errorf("模板内容为空")
	}

	targetMap := orderedmap.New()
	if err := json.Unmarshal([]byte(templateContent), &targetMap); err != nil {
		return "", fmt.Errorf("模板 JSON 解析失败: %w", err)
	}

	// 提取 _extra 控制逻辑
	var controlConfig TemplateLogicControlConfiguration
	if extraNode, exists := targetMap.Get("_extra"); exists {
		jsonBytes, _ := json.Marshal(extraNode)
		if err := json.Unmarshal(jsonBytes, &controlConfig); err != nil {
			return "", fmt.Errorf("解析 _extra 控制配置失败: %w", err)
		}
	} else {
		return "", fmt.Errorf("模板中未找到 _extra 控制字段")
	}

	// 提取订阅源任务
	var fetchTasks []ScheduledSubscriptionFetchTask
	for _, urlPair := range controlConfig.RemoteSubscriptionUrls {
		if len(urlPair) >= 2 {
			fetchTasks = append(fetchTasks, ScheduledSubscriptionFetchTask{
				SubscriptionLabel: urlPair[0],
				SubscriptionUrl:   urlPair[1],
			})
		}
	}

	if len(fetchTasks) == 0 {
		return "", fmt.Errorf("未在 _extra 中指定任何有效的订阅源 (sub_urls)")
	}

	// 抓取并解析节点，订阅请求最多等待 30 秒。
	nodes, err := fetchAndConvertProxies(fetchTasks, controlConfig)
	if err != nil {
		return "", err
	}
	if len(nodes) == 0 {
		return "", fmt.Errorf("从所有订阅源中均未获取到有效节点")
	}

	// 注入并组装
	finalMap := injectNodesAndGroups(targetMap, controlConfig, nodes)

	var outputBuffer bytes.Buffer
	jsonEncoder := json.NewEncoder(&outputBuffer)
	jsonEncoder.SetEscapeHTML(false)
	jsonEncoder.SetIndent("", "  ")
	if err := jsonEncoder.Encode(finalMap); err != nil {
		return "", fmt.Errorf("生成最终 JSON 失败: %w", err)
	}

	return outputBuffer.String(), nil
}

func fetchAndConvertProxies(
	fetchTasks []ScheduledSubscriptionFetchTask,
	controlConfig TemplateLogicControlConfiguration,
) ([]StandardSingBoxOutboundConfiguration, error) {

	finalNodes := []StandardSingBoxOutboundConfiguration{}
	registry := make(map[string]bool)

	var filterRegex *regexp.Regexp
	if controlConfig.NodeFilterRegexPattern != "" {
		var err error
		filterRegex, err = regexp.Compile("(?i)" + controlConfig.NodeFilterRegexPattern)
		if err != nil {
			return nil, fmt.Errorf("过滤正则表达式语法错误: %w", err)
		}
	}

	// 与独立 sub-tools 保持一致：订阅请求超时为 30 秒。
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	var fetchErrors []string

	for _, task := range fetchTasks {
		rawContent, err := downloadRawSubscriptionContentWithTimeout(httpClient, task.SubscriptionUrl)
		if err != nil {
			fetchErrors = append(fetchErrors, fmt.Sprintf("[%s] 请求失败: %v", task.SubscriptionLabel, err))
			continue
		}

		decodedContent, decErr := AttemptRobustBase64DecodingOfSubscriptionContent(rawContent)
		if decErr != nil {
			decodedContent = rawContent
		}

		lines := strings.Split(decodedContent, "\n")
		for _, line := range lines {
			sanitized := strings.TrimSpace(line)
			if sanitized == "" {
				continue
			}

			node, convErr := ConvertRawSubscriptionProtocolUriIntoStandardSingBoxOutbound(sanitized)
			if convErr != nil || node == nil {
				continue
			}

			if filterRegex != nil && filterRegex.MatchString(node.Tag) {
				continue
			}

			fingerprint := fmt.Sprintf("%s:%d:%s", node.ServerAddress, node.ServerPort, node.Tag)
			if registry[fingerprint] {
				continue
			}

			finalNodes = append(finalNodes, *node)
			registry[fingerprint] = true
		}
	}

	// 如果所有源均拉取失败，返回具体错误汇总
	if len(finalNodes) == 0 && len(fetchErrors) > 0 {
		return nil, fmt.Errorf("所有订阅抓取失败:\n%s", strings.Join(fetchErrors, "\n"))
	}

	return finalNodes, nil
}

// downloadRawSubscriptionContentWithTimeout 下载订阅正文，限制响应大小并避免错误提示泄露订阅令牌。
func downloadRawSubscriptionContentWithTimeout(subscriptionHttpClient *http.Client, subscriptionUrl string) (string, error) {
	subscriptionRequest, requestCreationError := http.NewRequest(http.MethodGet, subscriptionUrl, nil)
	if requestCreationError != nil {
		return "", fmt.Errorf("订阅地址格式无效")
	}
	// 与独立 sub-tools 使用相同的 User-Agent，避免订阅服务返回完整配置而非分享链接。
	subscriptionRequest.Header.Set("User-Agent", "Go-http-client/1.1")
	subscriptionResponse, requestError := subscriptionHttpClient.Do(subscriptionRequest)
	if requestError != nil {
		return "", fmt.Errorf("订阅请求失败（网络错误或超时）")
	}
	defer subscriptionResponse.Body.Close()
	if subscriptionResponse.StatusCode < 200 || subscriptionResponse.StatusCode >= 300 {
		return "", fmt.Errorf("订阅服务器返回 HTTP %d", subscriptionResponse.StatusCode)
	}
	const maximumSubscriptionResponseBodySizeInBytes = 16 << 20
	responseBodyBytes, responseReadError := io.ReadAll(io.LimitReader(subscriptionResponse.Body, maximumSubscriptionResponseBodySizeInBytes+1))
	if responseReadError != nil {
		return "", fmt.Errorf("订阅正文读取失败")
	}
	if len(responseBodyBytes) > maximumSubscriptionResponseBodySizeInBytes {
		return "", fmt.Errorf("订阅正文超过 16 MiB 限制")
	}
	subscriptionContent := strings.TrimSpace(strings.TrimPrefix(string(responseBodyBytes), "\ufeff"))
	if subscriptionContent == "" {
		return "", fmt.Errorf("订阅正文为空")
	}
	return subscriptionContent, nil
}

func injectNodesAndGroups(
	templateMap *orderedmap.OrderedMap,
	controlConfig TemplateLogicControlConfiguration,
	availableNodes []StandardSingBoxOutboundConfiguration,
) *orderedmap.OrderedMap {

	var allNodeTags []string
	for _, node := range availableNodes {
		allNodeTags = append(allNodeTags, node.Tag)
	}

	var dynamicGroups []StandardSingBoxOutboundConfiguration
	var allRegionTags []string

	for _, regionRule := range controlConfig.RegionalGroupConfigs {
		if len(regionRule) < 2 {
			continue
		}
		label, pattern := regionRule[0], regionRule[1]
		reg, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue
		}

		var matchedTags []string
		for _, tag := range allNodeTags {
			if reg.MatchString(tag) {
				matchedTags = append(matchedTags, tag)
			}
		}

		if len(matchedTags) > 0 {
			group := StandardSingBoxOutboundConfiguration{
				Type:                "urltest",
				Tag:                 label,
				Outbounds:           matchedTags,
				ConnectivityTestUrl: "https://www.gstatic.com/generate_204",
				TestInterval:        "3m",
				ToleranceValue:      150,
			}
			dynamicGroups = append(dynamicGroups, group)
			allRegionTags = append(allRegionTags, label)
		}
	}

	if rawOutbounds, exists := templateMap.Get("outbounds"); exists {
		originalList := rawOutbounds.([]interface{})
		var newList []interface{}

		for _, item := range originalList {
			if placeholder, isStr := item.(string); isStr {
				if placeholder == "<dynamic-region-groups>" {
					for _, rg := range dynamicGroups {
						newList = append(newList, rg)
					}
				} else {
					newList = append(newList, placeholder)
				}
				continue
			}

			if objMap, isMap := item.(orderedmap.OrderedMap); isMap {
				if subOutbounds, hasSub := objMap.Get("outbounds"); hasSub {
					subTags := subOutbounds.([]interface{})
					var expandedTags []string
					for _, t := range subTags {
						tagName, _ := t.(string)
						switch tagName {
						case "<all-proxies>":
							expandedTags = append(expandedTags, allNodeTags...)
						case "<all-region-groups>":
							expandedTags = append(expandedTags, allRegionTags...)
						default:
							expandedTags = append(expandedTags, tagName)
						}
					}
					objMap.Set("outbounds", expandedTags)
				}
				newList = append(newList, objMap)
			}
		}

		for _, node := range availableNodes {
			newList = append(newList, node)
		}
		templateMap.Set("outbounds", newList)
	}

	templateMap.Delete("_extra")
	return templateMap
}
