package libbox

import (
"github.com/sagernet/sing-box/experimental/libbox/subtool"
)

// ProcessTemplate 导出给 Android / Apple 客户端调用
func ProcessTemplate(templateContent string) (string, error) {
return subtool.ProcessTemplateString(templateContent)
}
