const david = nacl.box.keyPair();

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
        password: davidEncrypting(publicKey, password),
        publicKey: david.publicKey,
      }),
    });

    const userData = await user.json();
    text.innerHTML = userData;
  } catch (err) {
    text.innerHTML = JSON.stringify(`Error: ${err}`);
  }
}

function davidEncrypting(publicKey, password) {
  // David computes a one time shared key
  const david_shared_key = nacl.box.before(publicKey, david.secretKey);
  //David also computes a one time code.
  const one_time_code = nacl.randomBytes(24);
  //Davids message
  //Getting the cipher text
  const cipher_text = nacl.box.after(
    nacl.util.decodeUTF8(password),
    one_time_code,
    david_shared_key
  );
  //message to be transited.
  const message_in_transit = { cipher_text, one_time_code };
  return message_in_transit;
}
