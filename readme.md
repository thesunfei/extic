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
                        path: /^(\/admin\/api|\/admin\/expand)/,
                        url: "https://www.google.com",
                        replace: "" //The matched substring of request url will be replaced by this value,the usage is the same as String.replace.In this example,if the request path was "/admin/abcd",the actual request url will be "https://google.com/abcd".Default is "$&"
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
                index: "index.html"
            },
            {
                name: "test2",
                domains: ["test4.com", "www.test4.com"],
                dir: "/home/web/test4",
                index: "index.html"
            }
        ],
        protocol: "https",
        cert: {
            key: "../certs/web.key", //The path is relative to the directory of the config file
            cert: "/home/certs/web.crt"
        },
        port: 443
    }]
}
```

## Change logs
```
v1.4.10:
Fixed proxy crash issue and changed line endings to lf;
v1.4.9:
File upload for proxy supported;
v1.4.8:
Added replace function for proxy;
v1.4.7:
Added preventing git config files stealing attack;
v1.4.3:
Proxy bug fixed; 
v1.4.2: 
Colorful console output supported;
Relative path for config file and server files supported;
Custom headers supported;
Log is now enabled by default;

```