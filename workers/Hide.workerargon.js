import JSZip from "jszip";
import { argon2 } from "argon2-browser"; // Import the Argon2 library

const encryptZip = async (zipUint, imageUint, password) => {
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
        ["encrypt"]
    );

    const zipEncrypted = await crypto.subtle.encrypt(
        {
            name: "AES-CTR",
            counter: new Uint8Array(16), // Counter should be 16 bytes
            length: 128,
        },
        cryptoKey,
        zipUint.buffer
    );

    return new Uint8Array(zipEncrypted);
};

onmessage = async ({
    data: {
        image: [{ contents, type }],
        files,
        compression,
        password,
    },
}) => {
    const zip = new JSZip();
    files.forEach((file) => {
        const { name, contents, date } = file;
        zip.file(name, contents, {
            date,
        });
    });

    const imageUint = new Uint8Array(contents);

    const zipUint = await zip.generateAsync(
        {
            type: "uint8array",
            compression: compression === 0 ? "STORE" : "DEFLATE",
            compressionOptions: {
                level: compression,
            },
        },
        ({ percent }) => {
            postMessage({ progress: percent });
        }
    );

    const zipEncryptedUint = await encryptZip(zipUint, imageUint, password);
    const resultUint = new Uint8Array([...imageUint, ...zipEncryptedUint]);

    postMessage({
        result: new Blob([resultUint], { type }),
    });
    close();
};
