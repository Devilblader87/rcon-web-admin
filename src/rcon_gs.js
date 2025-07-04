"use strict";

var dgram = require("dgram");
var events = require("events");

/**
 * RCON connection for Goldsource engine
 * Implements basic challenge/response protocol
 * @param {string} host
 * @param {number} port
 * @param {RconServer} server
 */
function RconGoldSource(host, port, server) {
    events.EventEmitter.call(this);

    this.host = host;
    this.port = port;
    this.server = server;

    this.socket = null;
    this.challenge = null;
    this.pending = [];
}

RconGoldSource.prototype = Object.create(events.EventEmitter.prototype);

/**
 * Connect to server and request challenge
 * @param {function=} callback
 * @returns {boolean} False if already connected
 */
RconGoldSource.prototype.connect = function (callback) {
    if (this.socket) return false;
    var self = this;
    this.socket = dgram.createSocket("udp4");
    this.socket.on("error", function (err) {
        if (callback) callback(err);
        self.disconnect();
    });
    this.socket.on("message", function (message) {
        self._onMessage(message);
    });
    var buf = Buffer.from("\xff\xff\xff\xffchallenge rcon\n");
    this.socket.send(buf, 0, buf.length, this.port, this.host, function (err) {
        if (err) {
            if (callback) callback(err);
            self.disconnect();
            return;
        }
    });
    this.once("auth", function () {
        if (callback) callback(null);
        self.emit("connect");
    });
    return true;
};

/**
 * Handle raw messages from server
 * @param {Buffer} msg
 * @private
 */
RconGoldSource.prototype._onMessage = function (msg) {
    if (msg.length < 5) return;
    if (msg.readInt32LE(0) !== -1) return;
    var str = msg.slice(4).toString();
    if (str.indexOf("challenge rcon") === 0) {
        var parts = str.split(" ");
        this.challenge = parts[2] ? parts[2].trim() : null;
        this.emit("auth", this.challenge !== null);
    } else {
        var response = {
            "size": msg.length - 4,
            "id": 0,
            "type": 0,
            "body": str,
            "user": null,
            "timestamp": new Date(),
            "log": true
        };
        if (this.pending.length) {
            var cb = this.pending.shift();
            if (cb) cb(str);
        }
        this.emit("message", response);
    }
};

/**
 * Send a command to server
 * @param {string|Buffer} cmd
 * @param {WebSocketUser|null} user
 * @param {boolean} log
 * @param {function} callback
 */
RconGoldSource.prototype.send = function (cmd, user, log, callback) {
    if (!this.socket || !this.challenge) {
        var err = new Error("Not connected");
        if (callback) callback(err);
        this.emit("error", err);
        return;
    }
    if (!Buffer.isBuffer(cmd)) cmd = Buffer.from(cmd);
    var message = Buffer.from(
        "\xff\xff\xff\xffrcon " + this.challenge + " \"" + this.server.serverData.rcon_password + "\" " + cmd.toString() + "\n"
    );
    this.socket.send(message, 0, message.length, this.port, this.host, function (err) {
        if (err && callback) callback(err);
    });
    if (callback) {
        this.pending.push(callback);
    }
};

/**
 * Disconnect
 * @returns {boolean} False if already disconnected
 */
RconGoldSource.prototype.disconnect = function () {
    if (!this.socket) return false;
    this.socket.close();
    this.socket = null;
    this.emit("disconnect");
    return true;
};

module.exports = RconGoldSource;
