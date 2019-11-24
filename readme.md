## **extic**

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
        port: 80
    }]
}
For Linux:
module.exports = {
    ports: [{
        sites: [{
                name: "test1",
                domains: ["test1.com", "www.test1.com"],
                dir: "/home/web/config.js",
                basePath:"/admin",
                index: "index.html"
            },
            {
                name: "test2",
                domains: ["test2.com", "www.test2.com"],
                dir: "/home/web/config.js",
                index: "index.html"
            }
        ],
        port: 80
    }]
}
```
