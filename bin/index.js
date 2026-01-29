#!/usr/bin/env node

const fs = require('fs');
const mime = require('mime');
const yargs = require('yargs');
const path = require('path');
const chalk = require('chalk');
const express = require('express');
const http = require('http');
const https = require('https');
const tls = require('node:tls');
const httpProxy = require('http-proxy');
const SecurityManager = require('./security');

const options = yargs
    .usage('Usage: -c <config>')
    .option('c', {
        alias: 'config',
        describe: 'Config file',
        type: 'string',
        demandOption: true
    })
    .argv;
const configPath = path.resolve(options.config);
const configPathParsed = path.parse(configPath);
const configDir = configPathParsed.dir;
try {
    var config = require(configPath);
} catch (e) {
    console.error(chalk.redBright(e + ':' + options.config || "''"));
    return;
}
const app = express();
app.use(express.json());

// 初始化安全模块
const security = new SecurityManager({
    dataDir: path.join(configDir, '.extic'),
    // 扫描检测配置
    scanThreshold: config.security?.scanThreshold || 20,
    scanTimeWindow: config.security?.scanTimeWindow || 60000,
    // 登录限制配置
    loginMaxAttempts: config.security?.loginMaxAttempts || 5,
    loginWindowMs: config.security?.loginWindowMs || 10 * 60 * 1000,
    loginLockoutMs: config.security?.loginLockoutMs || 60 * 60 * 1000,
    // 管理面板配置
    adminPath: config.security?.adminPath || '/__extic_admin__',
    adminPassword: config.security?.adminPassword || null,
    whitelist: config.security?.whitelist || ['127.0.0.1', '::1', '::ffff:127.0.0.1']
});

// 应用安全中间件
app.use(security.middleware());

console.log(chalk.cyan(`[Security] 管理面板: http://localhost:<port>${security.config.adminPath}`));

const proxyServer = httpProxy.createProxyServer({
    ignorePath: true
});
app.all('*', function (req, res) {
    var port;
    var host = req.get("host");
    res.setHeader("server", "extic");
    if (req.originalUrl.includes("/..")) {
        console.warn(chalk.yellowBright("Directory traversal attack detected! From ip: " + req.ip + ",URL: " + req.protocol + "://" + host + req.originalUrl));
        return;
    }
    if (req.originalUrl.includes("/.git")) {
        console.warn(chalk.yellowBright("Git config file stealing attack detected! From ip: " + req.ip + ",URL: " + req.protocol + "://" + host + req.originalUrl));
        return;
    }
    if (!host) {
        console.warn(chalk.yellowBright("Bad request with no host header,from ip: " + req.ip + ",URL: " + req.protocol + "://" + host + req.originalUrl));
        res.status(400).send("Bad Request");
        return;
    }
    if (host.replace(req.hostname, "") != "") {
        port = host.split(":")[1]
    } else {
        if (req.protocol == "http") {
            port = 80;
        } else if (req.protocol == "https") {
            port = 443;
        }
    }
    var matched = false;
    if (config.ports.some(v => v.port == port)) {
        config.ports.find(v => v.port == port).sites.forEach(site => {
            if (matched) return;
            if (site.headers) {
                for (let name in site.headers) {
                    res.setHeader(name, site.headers[name]);
                }
            };
            if (site.log || site.log === undefined) {
                console.log(chalk.green(new Date().toLocaleString() + ", Got request from ip " + req.ip + ", URL: " + req.protocol + "://" + host + req.originalUrl));
            }
            let basePath = site.basePath || "/";
            if (site.domains.includes(req.hostname) && (new RegExp("^" + basePath.replace(/\/$/, "") + "\/").test(req.path) || req.path == basePath || req.path == basePath.replace(/\/$/, ""))) {
                if (site.proxy) {
                    if (!Array.isArray(site.proxy)) {
                        site.proxy = [site.proxy];
                    }
                    for (let proxy of site.proxy) {
                        if (proxy.path.test(req.path)) {
                            let proxyURL = proxy.url + req.originalUrl.replace(proxy.path, proxy.replace === undefined ? "$&" : proxy.replace);
                            let proxyURLObj = new URL(proxyURL);
                            proxyServer.web(req, res, {
                                target: proxyURL,
                                headers: {
                                    ...req.headers,
                                    host: proxyURLObj.host,
                                    origin: proxyURLObj.origin,
                                    referer: proxyURLObj.origin
                                },
                                ignorePath: true,
                                followRedirects: true,
                                ...proxy.options
                            });
                            proxyServer.on("proxyReq", function (proxyReq, req) {
                                console.log(chalk.cyan('Proxy Requested.URL:' + proxyURL));
                                if (req.body && Object.keys(req.body).length > 0 && req.complete) {
                                    let bodyData = req.body;
                                    if (typeof bodyData == "object") {
                                        bodyData = JSON.stringify(bodyData)
                                    }
                                    proxyReq.write(bodyData);
                                }
                            })
                            proxyServer.on("error", function (e) {
                                console.log(chalk.red("Proxy Failed [" + e.code + "].URL:" + proxyURL));
                                if (!req.complete) {
                                    res.status(502).send('Bad Gateway');
                                }
                            })
                            matched = true;
                            return
                        }
                    }

                }
                matched = true;
                const requestedFile = path.resolve(configDir, site.dir + req.path.replace(basePath.replace(/\/$/, ""), ""));
                fs.readFile(requestedFile, (err, data) => {
                    if (err) {
                        // 文件不存在，记录可疑请求（用于扫描检测）
                        security.recordSuspiciousRequest(req, false);
                        
                        // 前端路由：返回首页
                        fs.readFile(path.resolve(configDir, site.dir + "/" + site.index), (err, data) => {
                            if (err) {
                                res.type('html');
                                res.status(404).send('Index File Not Found');
                            } else {
                                res.type('html');
                                res.send(data);
                            }
                        });
                    } else {
                        res.type(mime.getType(requestedFile) || "text/plain");
                        res.send(data);
                    }
                });
            }
        });
    }
    if (!matched) {
        console.warn(chalk.yellowBright(new Date().toLocaleString() + ", No matched domain found or base path mismatched. " + req.ip + ",URL: " + req.protocol + "://" + host + req.originalUrl));
        res.type('html');
        res.status(406).send('Not Acceptable');
    }
});
config.ports.forEach(port => {
    try {
        if ((port.protocol || "").toLowerCase().trim() == "http" || port.protocol === undefined) {
            http.createServer(app).listen(port.port);
        } else if ((port.protocol || "").toLowerCase().trim() == "https") {
            https.createServer({
                SNICallback(domain, cb){
                    let site = port.sites.find(v => v.domains.includes(domain));
                    if (site && site.cert) {
                        cb(null, tls.createSecureContext({
                            key: fs.readFileSync(path.resolve(configDir, site.cert.key)),
                            cert: fs.readFileSync(path.resolve(configDir, site.cert.cert || site.cert.crt))
                        }))
                    } else {
                        cb(null, tls.createSecureContext({
                            key: fs.readFileSync(path.resolve(configDir, port.cert.key)),
                            cert: fs.readFileSync(path.resolve(configDir, port.cert.cert || port.cert.crt))
                        }))
                    }
                },
                key: fs.readFileSync(path.resolve(configDir, port.cert.key)),
                cert: fs.readFileSync(path.resolve(configDir, port.cert.cert || port.cert.crt))
            }, app).listen(port.port);
        }
        port.sites.forEach(site => {
            console.log(chalk.greenBright(site.name + " running on:"));
            console.log(chalk.greenBright(site.domains.map(v => (port.protocol || "http") + "://" + v + ":" + port.port).join(', ')));
        });
    } catch (e) {
        console.error(chalk.redBright(e));
    }
});