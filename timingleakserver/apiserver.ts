import express = require("express");
import CryptoJS = require("crypto-js");
const app = express();


const key = "super secret key";
const testmessage = "hello"

const sleeptime = 3

const hmacsha1 = (key: string, message: string) => {
    const hm = CryptoJS.HmacSHA1(message, key);
    return CryptoJS.enc.Hex.stringify(hm);
};

const sleep = (ms: number) => {
    return new Promise((resolve: any) => setTimeout(resolve, ms));
};

const insecurecompare = async (code1: string, code2: string) => {
    console.log("c1:", code1);
    console.log("c2:", code2);
    for (var i = 1; i < code1.length; i = i + 2) {
        if ( code1[i-1] !== code2[i-1] || code1[i] !== code2[i] ){
            return false;
        }
        await sleep(sleeptime);
    }
    return true;
};

app.get('/ch31', (req, res) => {
    let file = req.query.file;
    let signature = req.query.signature;
    let code = hmacsha1(key, file);
    insecurecompare(code, signature).then((eql: boolean) => {
        if(eql){
            return res.status(200).send({ message: "OK" });
        } else {
            return res.status(500).send({ message: "Invalid" });
        }
    });
});

console.log("test code", hmacsha1(key, testmessage))
console.log("Artificial delay: ", sleeptime)
app.listen(3000, () => console.log('listening on port 3000'));