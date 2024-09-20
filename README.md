# utils
utils

修改版本标签号

标签要推向远程后

go get github.com/fpfgithub/utils@latest
拉取最新版本
执行报错
imports
        github.com/fpfgithub/utils: github.com/fpfgithub/utils@v1.0.2: verifying module: github.com/fpfgithub/utils@v1.0.2: reading https://goproxy.cn/sumdb/sum.golang.org/lookup/github.com/fpfgithub/utils@v1.0.2: 404 Not Found
        server response: not found: github.com/fpfgithub/utils@v1.0.2: invalid version: unknown revision v1.0.2


在 PowerShell 中设置 HTTP 代理，你可以使用环境变量的方式。以下是命令：
设置 HTTP 代理:
$Env:http_proxy="http://127.0.0.1:10809"
$Env:https_proxy="http://127.0.0.1:10809"
CMD
   set http_proxy=http://127.0.0.1:10809
   set https_proxy=http://127.0.0.1:10809

$env:GOPROXY="direct"; go get github.com/fpfgithub/utils@latest