const nacl = require("tweetnacl");
nacl.util = require("tweetnacl-util");

const serverPair = nacl.box.keyPair();

function serverDecrypting(message, publicKey) {
  //Getting Server's shared key
  const server_shared_key = nacl.box.before(publicKey, serverPair.secretKey);
  //Get the decoded message
  let decoded_message = nacl.box.open.after(
    message.cipher_text,
    message.one_time_code,
    server_shared_key
  );
  //Get the human readable message
  let plain_text = nacl.util.encodeUTF8(decoded_message);
  // return the message
  return plain_text;
}

const http = require("http");

const port = process.env.PORT || 3000;

const server = http.createServer().on("request", async (req, res) => {
  res.statusCode = 200;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "OPTIONS, POST");
  res.setHeader("Access-Control-Max-Age", 2592000); // 30 days

  if (req.method === "OPTIONS") {
    res.write(JSON.stringify(serverPair.publicKey));
  } else if (req.method === "POST") {
    const buffers = [];

    for await (const chunk of req) {
      buffers.push(chunk);
    }

    const data = Buffer.concat(buffers).toString();
    const user = JSON.parse(data);
    const password = serverDecrypting(
      {
        cipher_text: new Uint8Array(Object.values(user.password.cipher_text)),
        one_time_code: new Uint8Array(
          Object.values(user.password.one_time_code)
        ),
      },
      new Uint8Array(Object.values(user.publicKey))
    );
    res.write(JSON.stringify(password));
  }
  res.end();
});

server.listen(port, () => {
  console.log(`Server running at port ${port}`);
});
