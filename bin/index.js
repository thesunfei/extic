#!/usr/bin/env node

const fs = require('fs');
const mime = require('mime');
const yargs = require('yargs');
const path = require('path');
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
try {
    var config = require(options.config);
} catch (e) {
    console.error(e.code + ':' + options.config || "''");
    return;
}
const app = express();
const platform = os.type();
const pathSplit = platform == 'Windows_NT' ? '\\' : '/';
app.all('*', function (req, res) {
    var port;
    var host = req.get("host");
    if (!host) {
        console.error("Bad request with no host header,from client ip: " + req.ip + ",url: " + req.protocol + "://" + req.hostname + ":" + port + req.originalUrl);
        req.status(400).send("Bad Request");
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
    if (config.log) {
        console.log(new Date().toLocaleString()+", Got request from ip " + req.ip + ", url:" + req.protocol + "://" + req.hostname + ":" + port + req.originalUrl);
    }
    var matched = false;
    if (config.ports.find(v => v.port == port)) {
        config.ports.find(v => v.port == port).sites.forEach(site => {
            if (matched) return;
            let basePath = site.basePath || "/";
            if (site.domains.includes(req.hostname) && (new RegExp("^" + basePath.replace(/\/$/, "") + "\/").test(req.path) || req.path == basePath || req.path == basePath.replace(/\/$/, ""))) {
                matched = true;
                fs.readFile(site.dir + req.path.replace(basePath.replace(/\/$/, ""), ""), (err, data) => {
                    if (err) {
                        fs.readFile(path.normalize(site.dir + pathSplit + site.index), (err, data) => {
                            if (err) {
                                res.type('html');
                                res.status(404).send('Index File Not Found');
                            } else {
                                res.type('html');
                                res.send(data);
                            }
                        });
                    } else {
                        res.type(mime.getType(path.normalize(site.dir + pathSplit + req.path.replace(/\//g, pathSplit))) || "text/plain");
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
        if (port.protocol == "http" || port.protocol == undefined) {
            http.createServer(app).listen(port.port);
        } else if (port.protocol == "https") {
            https.createServer({
                key: fs.readFileSync(port.cert.key),
                cert: fs.readFileSync(port.cert.cert || port.cert.crt)
            }, app).listen(port.port);
        }
        port.sites.forEach(site => {
            console.log(site.name + " running on:");
            console.log(site.domains.map(v => (port.protocol || "http") + "://" + v + ":" + port.port).join(', '));
        });
    } catch (e) {
        console.error(e);
    }
});