## **extic**
```
A simple configurable static http and https server powered by Express.js,supported proxy, custom headers and frontend router.
```

## Install
```
npm i -g extic
```

## Run your servers
```
extic -c <config>

example:
extic -c ./web/config.js
```

## 🛡️ Security Features (v1.5.0+)

### Web 管理面板
访问 `http://your-domain/__extic_admin__` 查看：
- 今日访问统计
- 访客 IP 及其访问记录
- 一键拉黑/解除拉黑功能
- 黑名单管理

### 自动防护
- **扫描器检测**：如果某 IP 在 1 分钟内访问超过 10 个不存在的文件，自动拉黑
- **目录遍历攻击检测**：自动拦截 `/../` 请求
- **Git 文件窃取检测**：自动拦截 `/.git` 请求
- **黑名单持久化**：重启后黑名单依然有效

### 配置选项
```javascript
module.exports = {
    security: {
        notFoundThreshold: 10,        // 404 次数阈值（默认 10）
        timeWindow: 60000,            // 统计时间窗口，毫秒（默认 1 分钟）
        adminPath: '/__extic_admin__', // 管理面板路径
        adminPassword: 'your-secret', // 管理面板密码（强烈建议设置！）
        whitelist: ['127.0.0.1']      // IP 白名单（永不拉黑）
    },
    ports: [...]
}
```

> ⚠️ **安全提示**：生产环境请务必设置 `adminPassword`，否则任何人都可以访问管理面板！

### Config file examples
```

module.exports = {
    ports: [{
        sites: [{
                name: "test1",//The name of you website
                domains: ["test1.com", "www.test1.com"],
                dir: "/home/web/test1", //The root path of your website files
                basePath:"/admin", //The root path of the website URL.
                index: "index.html", //For frontend router usage.
                headers:{ //Custom response headers
                    test:"test"
                },
                proxy: [{
                        path: /^(\/admin|\/api)/,
                        url: "https://www.google.com",
                        replace: "", //The matched substring of request url will be replaced by this value,the usage is the same as String.replace.In this example,if the request path was "/admin/abcd",the actual request url will be "https://google.com/abcd".Default is "$&"
                        options:{ //See https://github.com/http-party/node-http-proxy#options for this usage.
                            followRedirects:true,//Default:true
                            ignorePath:true //Default:true
                        }
                    },
                    {
                        path: /^(\/admin\/test1|\/admin\/test2)/,
                        url: "https://www.bing.com",
                        replace: function(match){return match+"/"+match}
                }],
                log:true //Whether to output user visit logs in console.Default is true.
            },
            {
                name: "test2",
                domains: ["test2.com", "www.test2.com"],
                dir: "../web/test2",//The path is relative to the directory of the config file
                index: "index.html"
            }
        ],
        port: 80
    },
    {
        sites: [{
                name: "test3",
                domains: ["test3.com", "www.test3.com"],
                dir: "./web/test3",
                basePath:"/admin",
                index: "index.html",
                cert: {
                    key: "../certs/test3.key", //The path is relative to the directory of the config file
                    cert: "/home/certs/test3.crt"
                }
            },
            {
                name: "test2",
                domains: ["test4.com", "www.test4.com"],
                dir: "/home/web/test4",
                index: "index.html",
                cert: {
                    key: "../certs/test4.key", //The path is relative to the directory of the config file
                    cert: "/home/certs/test4.crt"
                }
            }
        ],
        protocol: "https",
        cert: {//Required，this is the fallback cert if no matched domain found;
            key: "../certs/web.key", //The path is relative to the directory of the config file
            cert: "/home/certs/web.crt"
        },
        port: 443
    }]
}
```

## Change logs
```
v1.5.0:
Added security features:
- Web admin panel for monitoring visitors
- IP blacklist with one-click blocking
- Auto-block scanners (too many 404s)
- Persistent blacklist storage

v1.4.15:
Supported different SSL certs for different domains.

```