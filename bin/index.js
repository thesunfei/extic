#!/usr/bin/env node

const fs = require('fs');
const mime = require('mime');
const yargs = require('yargs');
const path = require('path');
const chalk = require('chalk');
const os = require('os');
const express = require('express');
const http = require('http');
const https = require('https');
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
app.all('*', function (req, res) {
    var port;
    var host = req.get("host");
    res.setHeader("server", "extic");
    if (req.originalUrl.includes("/..")) {
        console.warn(chalk.yellowBright("Directory traversal attack detected! From ip: " + req.ip + ",URL: " + req.protocol + "://" + host + req.originalUrl));
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
                console.log(chalk.greenBright(new Date().toLocaleString() + ", Got request from ip " + req.ip + ", URL: " + req.protocol + "://" + host + req.originalUrl));
            }
            if (site.proxy) {
                if (site.proxy.path.test(req.path)) {
                    let requestClient;
                    if (/^http:/.test(site.proxy.url)) {
                        requestClient = http;
                    } else if (/^https:/.test(site.proxy.url)) {
                        requestClient = https;
                    }
                    requestClient.get(site.proxy.url + req.originalUrl, {
                        headers: req.headers
                    }, r => {
                        r.rawHeaders.forEach((item, index) => {
                            if (index % 2 == 0) {
                                res.append(item, r.rawHeaders[index + 1])
                            }
                        })
                        r.on('data', dt => {
                            res.write(dt)
                        })
                        r.on('end', () => {
                            res.end();
                        })
                        console.log(chalk.green("Proxy operation finished."));
                    })
                    matched = true;
                    return
                }
            }
            let basePath = site.basePath || "/";
            if (site.domains.includes(req.hostname) && (new RegExp("^" + basePath.replace(/\/$/, "") + "\/").test(req.path) || req.path == basePath || req.path == basePath.replace(/\/$/, ""))) {
                matched = true;
                fs.readFile(path.resolve(configDir, site.dir + req.path.replace(basePath.replace(/\/$/, ""), "")), (err, data) => {
                    if (err) {
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
                        res.type(mime.getType(path.resolve(configDir, site.dir + "/" + req.path)) || "text/plain");
                        res.send(data);
                    }
                });
            }
        });
    }
    if (!matched) {
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