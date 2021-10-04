const clientPair = nacl.box.keyPair();

async function submit() {
  const text = document.getElementById("result");
  const input = document.getElementById("password");
  const password = input.value;
  try {
    const res = await fetch("http://localhost:3000", {
      method: "OPTIONS",
    });
    const data = await res.json();
    const publicKey = new Uint8Array(Object.values(data));

    const user = await fetch("http://localhost:3000", {
      method: "POST",
      body: JSON.stringify({
        username: "admin",
        password: clientEncrypting(publicKey, password),
        publicKey: clientPair.publicKey,
      }),
    });

    const userData = await user.json();
    text.innerHTML = userData;
  } catch (err) {
    text.innerHTML = JSON.stringify(`Error: ${err}`);
  }
}

function clientEncrypting(publicKey, password) {
  // Client computes a one time shared key
  const client_shared_key = nacl.box.before(publicKey, clientPair.secretKey);
  //Client also computes a one time code.
  const one_time_code = nacl.randomBytes(24);
  //Clients message
  //Getting the cipher text
  const cipher_text = nacl.box.after(
    nacl.util.decodeUTF8(password),
    one_time_code,
    client_shared_key
  );
  //message to be transited.
  const message_in_transit = { cipher_text, one_time_code };
  return message_in_transit;
}
