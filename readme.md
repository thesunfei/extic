## **extic**

## Install
```
npm i -g extic
```

## Run your servers
```
extic -c <config>

example:
extic -c c:\web\config.js
```

### Config file examples
```
For Windows:
module.exports = {
    ports: [{
        sites: [{
                name: "test1",
                domains: ["test1.com", "www.test1.com"],
                dir: "c:\\sites\\test1",
                basePath:"/admin",
                index: "index.html"
            },
            {
                name: "test2",
                domains: ["test2.com", "www.test2.com"],
                dir: "c:\\sites\\test1",
                index: "index.html"
            }
        ],
        protocol: "http",
        port: 80
    },
    {
        sites: [{
                name: "test3",
                domains: ["test3.com", "www.test3.com"],
                dir: "c:\\sites\\test3",
                basePath:"/admin",
                index: "index.html"
            },
            {
                name: "test4",
                domains: ["test4.com", "www.test4.com"],
                dir: "c:\\sites\\test4",
                index: "index.html"
            }
        ],
        protocol: "https",
        cert: {
            key: "c:\\sites\\certs\\web.key",
            cert: "c:\\sites\\certs\\web.crt"
        },
        port: 443
    }]
}

For Linux:
module.exports = {
    ports: [{
        sites: [{
                name: "test1",
                domains: ["test1.com", "www.test1.com"],
                dir: "/home/web/test1",
                basePath:"/admin",
                index: "index.html"
            },
            {
                name: "test2",
                domains: ["test2.com", "www.test2.com"],
                dir: "/home/web/test2",
                index: "index.html"
            }
        ],
        port: 80
    },
    {
        sites: [{
                name: "test3",
                domains: ["test3.com", "www.test3.com"],
                dir: "/home/web/test3",
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
            key: "/home/web/web.key",
            cert: "/home/web/web.crt"
        },
        port: 443
    }]
}
```
