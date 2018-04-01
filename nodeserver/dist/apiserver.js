"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const express = require("express");
const CryptoJS = require("crypto-js");
const app = express();
const key = "super secret key";
const testmessage = "hello";
const sleeptime = 3;
const hmacsha1 = (key, message) => {
    const hm = CryptoJS.HmacSHA1(message, key);
    return CryptoJS.enc.Hex.stringify(hm);
};
const sleep = (ms) => {
    return new Promise((resolve) => setTimeout(resolve, ms));
};
const insecurecompare = (code1, code2) => __awaiter(this, void 0, void 0, function* () {
    console.log("c1:", code1);
    console.log("c2:", code2);
    for (var i = 1; i < code1.length; i = i + 2) {
        if (code1[i - 1] !== code2[i - 1] || code1[i] !== code2[i]) {
            return false;
        }
        yield sleep(sleeptime);
    }
    return true;
});
app.get('/ch31', (req, res) => {
    let file = req.query.file;
    let signature = req.query.signature;
    let code = hmacsha1(key, file);
    insecurecompare(code, signature).then((eql) => {
        if (eql) {
            return res.status(200).send({ message: "OK" });
        }
        else {
            return res.status(500).send({ message: "Invalid" });
        }
    });
});
console.log("test code", hmacsha1(key, testmessage));
console.log("Artificial delay: ", sleeptime);
app.listen(3000, () => console.log('listening on port 3000'));
