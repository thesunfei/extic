#!/usr/bin/env node
const fs = require('fs');
const mime = require('mime');
const yargs = require('yargs');
const path = require('path');
const os = require('os');
const express = require('express');
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
    console.error(e.code+':'+options.config||"''");
    return;
}
const app = express();
const platform = os.type();
const pathSplit = platform == 'Windows_NT' ? '\\' : '/';
config.ports.forEach(port => {
    app.get('*', (req, res) => {
        var matched = false;
        port.sites.forEach(site => {
            let basePath=site.basePath||"/";
            if (site.domains.includes(req.hostname)&&(new RegExp("^"+basePath.replace(/\/$/,"")+"\/").test(req.path)||req.path==basePath||req.path==basePath.replace(/\/$/,""))) {
                matched = true;
                fs.readFile(site.dir + req.path.replace(basePath.replace(/\/$/,""),""), (err, data) => {
                    if (err) {
                        fs.readFile(path.normalize(site.dir + pathSplit + site.index), 'utf8', (err, data) => {
                            if (err) {
                                res.type('html');
                                res.status(404).send('Index File Not Found');
                            } else {
                                res.type('html');
                                res.send(data);
                            }
                        });
                    } else {
                        res.type(mime.getType(path.normalize(site.dir + pathSplit + req.path.replace(/\//g, pathSplit))));
                        res.send(data);
                    }
                });
            }
        });
        if (!matched) {
            res.type('html');
            res.status(406).send('Not Acceptable');
        }
    });
    app.listen(port.port, () => {
        port.sites.forEach(site => {
            console.log(site.name + ':' + site.domains.join(',') + ' running on port ' + port.port);
        });
    });
});