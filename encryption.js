import crypto from 'crypto';

const algorithm = 'aes-256-cbc';
const password = process.env.ENCRYPTION_PASSWORD;

function encrypt(buffer) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return Buffer.concat([iv, encrypted]);
}

function decrypt(encryptedBuffer) {
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = encryptedBuffer.slice(0, 16);
    const encrypted = encryptedBuffer.slice(16);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

export { encrypt, decrypt };
