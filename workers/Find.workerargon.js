import { argon2 } from "argon2-browser"; // Import the Argon2 library

const decryptZip = async (zipUint, imageUint, password) => {
    const passwordUint = new TextEncoder().encode(password);

    // Derive the key using Argon2
    const argon2Options = {
        pass: passwordUint, // password as Uint8Array
        salt: imageUint.slice(0, 16), // Use the first 16 bytes of imageUint as the salt
        time: 1, // Argon2 parameter: number of iterations
        mem: 1024, // Argon2 parameter: memory usage in KiB
        hashLen: 16, // length of the generated key
        parallelism: 1, // number of threads
        type: argon2.ArgonType.Argon2id, // Argon2id is the recommended version for password hashing
    };

    const hash = await argon2.hash(argon2Options); // Derive the key using Argon2

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        hash.hash, // Use the derived key from Argon2
        {
            name: "AES-CTR",
            length: 128,
        },
        false,
        ["decrypt"]
    );

    const zipDecrypted = await crypto.subtle.decrypt(
        {
            name: "AES-CTR",
            counter: new Uint8Array(16), // Counter should be 16 bytes
            length: 128,
        },
        cryptoKey,
        zipUint.buffer
    );

    return new Uint8Array(zipDecrypted);
};

onmessage = async ({
    data: {
        image: [{ contents, type }],
        password,
    },
}) => {
    const imageUint = new Uint8Array(contents);

    const marker = {
        "image/png": [174, 66, 96, 130],
        "image/jpeg": [255, 217],
        "image/gif": [59],
    }[type];

    const indexOfZip =
        imageUint.findIndex(
            (_, index) =>
                imageUint.slice(index, index + marker.length).toString() ===
                marker.toString()
        ) + marker.length;

    const zipEncryptedUint = imageUint.slice(indexOfZip);
    const zipUint = await decryptZip(zipEncryptedUint, imageUint, password);

    postMessage({
        result: new Blob([zipUint], { type: "application/zip" }),
    });
    close();
};
