# sign-helper

一个签到脚本，目前支持zimuzu, v2ex, smzdm... 后续会不断添加

脚本依赖 jq，httpie，安装请参考https://stedolan.github.io/jq/download/ 和 https://github.com/jkbrzt/httpie

使用时将sign.config.json.simple中修改对应账号的账号密码，然后重命名成sign.config.json

```
Usage:
    # 直接运行后输入要签到的网站
    ./sign.sh 
    # 或者运行参数添加多个需要签到的类型
    ./sign.sh smzdm v2ex zimuzu
```
