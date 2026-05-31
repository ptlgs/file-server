import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs/promises';
import {createReadStream} from 'fs';
import os from 'os';
import path from 'path';
import axios from 'axios';
import {HttpsProxyAgent} from 'https-proxy-agent';
import {getFile, uploadFile} from './s3Client.js';
import {decrypt, encrypt} from './encryption.js';
import {DiskStore} from 'cache-manager-fs-hash';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import {Client as ESClient} from '@elastic/elasticsearch';
import PQueue from 'p-queue';
import { LRUCache } from 'lru-cache'

const esClient = new ESClient({
    node: process.env.ES_SERVER,
    auth: {
        username: process.env.ES_USERNAME,
        password: process.env.ES_PASSWORD,
    },
});

async function writeLogToElasticsearch(logEntry) {
    try {
        const {timestamp, user_id, file_name, file_url, file_size} = logEntry;

        const response = await esClient.index({
            index: 'file-server-logs',
            document: {
                timestamp,
                user_id,
                file_name,
                file_url,
                file_size
            }
        });
        return response;
    } catch (error) {
        console.error('Error writing log entry to Elasticsearch:', error);
        return null;
    }
}

const fileCache = new DiskStore({
    path: 'diskcache',
    ttl: 86400 * 3 * 1000,
    zip: false,
});

const hitCounter = new Map();

const MAX_FILE_SIZE = parseInt(process.env.MAX_UPLOAD_BYTES || `${500 * 1024 * 1024}`, 10);
const MAX_UPLOAD_CHUNK_SIZE = parseInt(process.env.MAX_UPLOAD_CHUNK_BYTES || `${8 * 1024 * 1024}`, 10);
const MAX_ENCRYPTED_CHUNK_SIZE = MAX_UPLOAD_CHUNK_SIZE + 1024 * 1024;
const CHUNK_UPLOAD_TTL_MS = parseInt(process.env.CHUNK_UPLOAD_TTL_MS || `${24 * 60 * 60 * 1000}`, 10);
const chunkUploadRoot = path.resolve(process.env.UPLOAD_TMP_DIR || path.join(os.tmpdir(), 'file-server-chunk-uploads'));

const app = express();

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({extended: true}));

// Set up multer with file size limit
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_FILE_SIZE
    }
});

// Configure axios to use proxy if PROXY env var is set
if (process.env.PROXY) {
    axios.defaults.proxy = false;
    axios.defaults.httpsAgent = new HttpsProxyAgent(process.env.PROXY);
}

app.use(express.static('public'));

function calculateSHA256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

function getUserInfo(req) {
    const updateToken = req.query.token;
    if (!updateToken) {
        return null;
    }

    try {
        return jwt.verify(updateToken, process.env.JWT_SECRET);
    } catch (error) {
        console.error('Token verification failed:', error.message);
        return null;
    }
}

function validateChunkUploadId(uploadId) {
    if (typeof uploadId !== 'string' || !/^[0-9a-fA-F-]{36}$/.test(uploadId)) {
        throw new Error('Invalid upload id');
    }
}

function getChunkUploadDir(uploadId) {
    validateChunkUploadId(uploadId);
    return path.join(chunkUploadRoot, uploadId);
}

async function ensureChunkUploadRoot() {
    await fs.mkdir(chunkUploadRoot, {recursive: true});
}

async function readChunkUploadMeta(uploadId) {
    const uploadDir = getChunkUploadDir(uploadId);
    const metaPath = path.join(uploadDir, 'meta.json');
    const rawMeta = await fs.readFile(metaPath, 'utf8');
    return {uploadDir, meta: JSON.parse(rawMeta)};
}

async function writeChunkUploadMeta(uploadDir, meta) {
    await fs.writeFile(path.join(uploadDir, 'meta.json'), JSON.stringify(meta, null, 2));
}

function getChunkPath(uploadDir, chunkIndex) {
    return path.join(uploadDir, `${chunkIndex}.part`);
}

function getExpectedChunkSize(meta, chunkIndex) {
    if (chunkIndex === meta.totalChunks - 1) {
        return meta.fileSize - (meta.chunkSize * chunkIndex);
    }
    return meta.chunkSize;
}

async function getReceivedChunkIndexes(uploadDir, meta) {
    const received = [];
    for (let i = 0; i < meta.totalChunks; i++) {
        try {
            const stat = await fs.stat(getChunkPath(uploadDir, i));
            if (stat.size === getExpectedChunkSize(meta, i)) {
                received.push(i);
            }
        } catch (error) {
            if (error.code !== 'ENOENT') {
                throw error;
            }
        }
    }
    return received;
}

async function readCompletedChunkUpload(uploadDir) {
    try {
        const rawCompleted = await fs.readFile(path.join(uploadDir, 'completed.json'), 'utf8');
        return JSON.parse(rawCompleted);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return null;
        }
        throw error;
    }
}

async function deleteChunkUpload(uploadId) {
    const uploadDir = getChunkUploadDir(uploadId);
    await fs.rm(uploadDir, {recursive: true, force: true});
}

async function removeChunkFiles(uploadDir, meta) {
    await Promise.all(Array.from({length: meta.totalChunks}, async (_, i) => {
        await fs.rm(getChunkPath(uploadDir, i), {force: true});
    }));
}

async function processAndUploadFileFromChunks(uploadDir, meta, userInfo) {
    const key = crypto.scryptSync(process.env.ENCRYPTION_PASSWORD, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const sha256Hash = crypto.createHash('sha256');
    const encryptedTempPath = path.join(uploadDir, 'encrypted-upload.tmp');
    const encryptedHandle = await fs.open(encryptedTempPath, 'w');

    try {
        await encryptedHandle.write(iv);

        for (let i = 0; i < meta.totalChunks; i++) {
            const chunkPath = getChunkPath(uploadDir, i);
            const chunkData = await fs.readFile(chunkPath);
            const expectedSize = getExpectedChunkSize(meta, i);

            if (chunkData.length !== expectedSize) {
                throw new Error(`Chunk ${i} has invalid size`);
            }

            sha256Hash.update(chunkData);
            const encryptedChunk = cipher.update(chunkData);
            if (encryptedChunk.length > 0) {
                await encryptedHandle.write(encryptedChunk);
            }
        }

        const encryptedFinal = cipher.final();
        if (encryptedFinal.length > 0) {
            await encryptedHandle.write(encryptedFinal);
        }
    } finally {
        await encryptedHandle.close();
    }

    const sha256 = sha256Hash.digest('hex');
    const encryptedStat = await fs.stat(encryptedTempPath);

    const newUrl = `/${sha256}/${meta.filename}`;

    try {
        await uploadFile(`${sha256}`, createReadStream(encryptedTempPath), {
            contentLength: encryptedStat.size,
        });

        await writeLogToElasticsearch({
            timestamp: new Date(),
            user_id: userInfo.userId,
            file_name: meta.filename,
            file_url: newUrl,
            file_size: meta.fileSize
        });
    } finally {
        await fs.rm(encryptedTempPath, {force: true});
    }

    return {sha256, newUrl};
}

async function cleanupStaleChunkUploads() {
    try {
        await ensureChunkUploadRoot();
        const entries = await fs.readdir(chunkUploadRoot, {withFileTypes: true});
        const now = Date.now();

        await Promise.all(entries.filter(entry => entry.isDirectory()).map(async (entry) => {
            const uploadDir = path.join(chunkUploadRoot, entry.name);
            try {
                const stat = await fs.stat(uploadDir);
                if (now - stat.mtimeMs > CHUNK_UPLOAD_TTL_MS) {
                    await fs.rm(uploadDir, {recursive: true, force: true});
                }
            } catch (error) {
                console.warn(`Failed to clean stale upload ${entry.name}:`, error.message);
            }
        }));
    } catch (error) {
        console.warn('Failed to clean stale chunk uploads:', error.message);
    }
}

cleanupStaleChunkUploads();
setInterval(cleanupStaleChunkUploads, Math.min(CHUNK_UPLOAD_TTL_MS, 60 * 60 * 1000));

app.get('/check-upload-permission', async (req, res) => {
    if (!getUserInfo(req)) {
        res.status(403).send({ok: false});
        return;
    }
    res.send({ok: true});
});


async function processAndUploadFile(buffer, originalFilename, userInfo) {
    const sha256 = calculateSHA256(buffer);
    const encryptedData = encrypt(buffer);

    await uploadFile(`${sha256}`, encryptedData);

    const newUrl = `/${sha256}/${originalFilename}`;

    await writeLogToElasticsearch({
        timestamp: new Date(),
        user_id: userInfo.userId,
        file_name: originalFilename,
        file_url: newUrl,
        file_size: buffer.length
    });

    return {sha256, newUrl};
}

app.post('/e', async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }

    try {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        const encryptedBuffer = Buffer.concat(chunks);

        if (encryptedBuffer.length > MAX_FILE_SIZE + 1024) {
            return res.status(400).json({error: 'File size exceeds the 500MB limit'});
        }

        // Extract IV and encrypted data
        const iv = encryptedBuffer.slice(0, 16);
        const encrypted = encryptedBuffer.slice(16);

        // Decrypt using pre-shared key
        const decrypted = await decryptBuffer(encrypted, iv);
        if (decrypted.length > MAX_FILE_SIZE) {
            return res.status(400).json({error: 'File size exceeds the 500MB limit'});
        }

        const filename = req.headers['x-filename'] || '______';
        const {newUrl} = await processAndUploadFile(decrypted, filename, userInfo);

        res.json({url: newUrl});
    } catch (error) {
        console.error('Error uploading file:', error);
        res.status(500).json({error: 'Error uploading file'});
    }
});


app.post('/e/chunk/init', async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }

    try {
        await ensureChunkUploadRoot();

        const filename = typeof req.body.filename === 'string' && req.body.filename.trim()
            ? req.body.filename.trim()
            : '______';
        const fileSize = Number(req.body.fileSize);
        const chunkSize = Number(req.body.chunkSize);
        const totalChunks = Number(req.body.totalChunks);

        if (!Number.isSafeInteger(fileSize) || fileSize <= 0 || fileSize > MAX_FILE_SIZE) {
            return res.status(400).json({error: 'Invalid file size'});
        }
        if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0 || chunkSize > MAX_UPLOAD_CHUNK_SIZE) {
            return res.status(400).json({error: 'Invalid chunk size'});
        }
        if (!Number.isSafeInteger(totalChunks) || totalChunks !== Math.ceil(fileSize / chunkSize)) {
            return res.status(400).json({error: 'Invalid chunk count'});
        }

        const uploadId = crypto.randomUUID();
        const uploadDir = getChunkUploadDir(uploadId);
        await fs.mkdir(uploadDir, {recursive: true});

        const meta = {
            uploadId,
            userId: userInfo.userId,
            filename,
            fileSize,
            chunkSize,
            totalChunks,
            createdAt: new Date().toISOString(),
        };

        await writeChunkUploadMeta(uploadDir, meta);

        res.json({
            ok: true,
            uploadId,
            chunkSize,
            totalChunks,
            received: []
        });
    } catch (error) {
        console.error('Error initializing chunk upload:', error);
        res.status(500).json({error: 'Error initializing upload'});
    }
});

app.post('/e/chunk/status', async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }

    try {
        const {uploadId} = req.body;
        const {uploadDir, meta} = await readChunkUploadMeta(uploadId);

        if (`${meta.userId}` !== `${userInfo.userId}`) {
            return res.status(403).send({ok: false});
        }

        const completed = await readCompletedChunkUpload(uploadDir);
        if (completed) {
            return res.json({
                ok: true,
                completed: true,
                url: completed.newUrl,
                received: Array.from({length: meta.totalChunks}, (_, i) => i),
                totalChunks: meta.totalChunks
            });
        }

        const received = await getReceivedChunkIndexes(uploadDir, meta);
        res.json({ok: true, completed: false, received, totalChunks: meta.totalChunks});
    } catch (error) {
        console.error('Error getting chunk upload status:', error);
        res.status(404).json({error: 'Upload session not found'});
    }
});

app.post('/e/chunk', express.raw({type: 'application/octet-stream', limit: MAX_ENCRYPTED_CHUNK_SIZE}), async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }

    try {
        const uploadId = req.headers['x-upload-id'];
        const chunkIndex = Number(req.headers['x-chunk-index']);
        const chunkSHA256 = req.headers['x-chunk-sha256'];

        if (!Number.isSafeInteger(chunkIndex)) {
            return res.status(400).json({error: 'Invalid chunk index'});
        }

        const {uploadDir, meta} = await readChunkUploadMeta(uploadId);

        if (`${meta.userId}` !== `${userInfo.userId}`) {
            return res.status(403).send({ok: false});
        }
        if (chunkIndex < 0 || chunkIndex >= meta.totalChunks) {
            return res.status(400).json({error: 'Chunk index out of range'});
        }
        if (!Buffer.isBuffer(req.body) || req.body.length < 32) {
            return res.status(400).json({error: 'Invalid chunk body'});
        }

        const completed = await readCompletedChunkUpload(uploadDir);
        if (completed) {
            return res.json({ok: true, completed: true, url: completed.newUrl});
        }

        const iv = req.body.slice(0, 16);
        const encrypted = req.body.slice(16);
        const decrypted = await decryptBuffer(encrypted, iv);
        const expectedChunkSize = getExpectedChunkSize(meta, chunkIndex);

        if (decrypted.length !== expectedChunkSize) {
            return res.status(400).json({error: 'Chunk size mismatch'});
        }

        if (typeof chunkSHA256 === 'string' && chunkSHA256.length > 0) {
            const actualSHA256 = calculateSHA256(decrypted);
            if (actualSHA256 !== chunkSHA256) {
                return res.status(400).json({error: 'Chunk checksum mismatch'});
            }
        }

        const chunkPath = getChunkPath(uploadDir, chunkIndex);
        const tmpPath = `${chunkPath}.${process.pid}.${Date.now()}.tmp`;
        await fs.writeFile(tmpPath, decrypted);
        await fs.rename(tmpPath, chunkPath);
        await fs.utimes(uploadDir, new Date(), new Date());

        res.json({ok: true, chunkIndex});
    } catch (error) {
        console.error('Error uploading chunk:', error);
        res.status(500).json({error: 'Error uploading chunk'});
    }
});

app.post('/e/chunk/complete', async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }

    try {
        const {uploadId} = req.body;
        const {uploadDir, meta} = await readChunkUploadMeta(uploadId);

        if (`${meta.userId}` !== `${userInfo.userId}`) {
            return res.status(403).send({ok: false});
        }

        const completed = await readCompletedChunkUpload(uploadDir);
        if (completed) {
            return res.json({url: completed.newUrl, sha256: completed.sha256, completed: true});
        }

        const received = await getReceivedChunkIndexes(uploadDir, meta);
        if (received.length !== meta.totalChunks) {
            const receivedSet = new Set(received);
            const missing = Array.from({length: meta.totalChunks}, (_, i) => i).filter(i => !receivedSet.has(i));
            return res.status(409).json({error: 'Missing chunks', missing, received});
        }

        const {sha256, newUrl} = await processAndUploadFileFromChunks(uploadDir, meta, userInfo);

        await fs.writeFile(path.join(uploadDir, 'completed.json'), JSON.stringify({
            sha256,
            newUrl,
            completedAt: new Date().toISOString(),
        }, null, 2));
        await removeChunkFiles(uploadDir, meta);
        await fs.utimes(uploadDir, new Date(), new Date());

        res.json({url: newUrl, sha256});
    } catch (error) {
        console.error('Error completing chunk upload:', error);
        res.status(500).json({error: 'Error completing upload'});
    }
});

app.delete('/e/chunk/:uploadId', async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }

    try {
        const {uploadId} = req.params;
        const {meta} = await readChunkUploadMeta(uploadId);
        if (`${meta.userId}` !== `${userInfo.userId}`) {
            return res.status(403).send({ok: false});
        }

        await deleteChunkUpload(uploadId);
        res.json({ok: true});
    } catch (error) {
        res.json({ok: true});
    }
});



app.post('/upload', upload.single('file'), async (req, res) => {
    const userInfo = getUserInfo(req);
    if (!userInfo) {
        res.status(403).send({ok: false});
        return;
    }
    try {
        const file = req.file;
        if (!file) {
            return res.status(400).json({error: 'No file uploaded'});
        }

        const {newUrl} = await processAndUploadFile(file.buffer, file.originalname, userInfo);

        res.json({url: newUrl});
    } catch (error) {
        if (error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({error: 'File size exceeds the 500MB limit'});
        }
        console.error('Error uploading file:', error);
        res.status(500).json({error: 'Error uploading file'});
    }
});

app.get('/:sha256/:filename', async (req, res) => {
    try {
        const {sha256, filename} = req.params;
        const key = `${sha256}`;

        // Set aggressive caching headers
        res.set({
            'Cache-Control': 'public, max-age=31536000, immutable',
            'ETag': `"${sha256}"`,
        });

        // Check if the file is in cache
        const cachedData = await fileCache.get(key);
        if (cachedData) {
            res.contentType(filename);
            return res.send(cachedData);
        }

        const encryptedData = await getFile(key);
        let fileData = decrypt(encryptedData);
        hitCounter.set(key, (hitCounter.get(key) || 0) + 1);

        if (hitCounter.get(key) >= 8 && fileData.length <= MAX_FILE_SIZE) {
            await fileCache.set(key, fileData);
        }

        res.contentType(filename);
        res.send(fileData);
    } catch (error) {
        console.error('Error serving file:', error);
        res.status(500).send('Error serving file');
    }
});

const imageUrlCache = new LRUCache({max: 500});

const domainsToAutoUploadImages = (process.env.DOMAINS_TO_AUTO_UPLOAD_IMAGES || "").split(',').filter(x => x);
const domainsToAutoUploadImagesExcept = (process.env.DOMAINS_TO_AUTO_UPLOAD_IMAGES_EXCEPT || "").split(',').filter(x => x);

let autoUploadEnabled = true;

if (domainsToAutoUploadImagesExcept.length > 0 && domainsToAutoUploadImages.length > 0) {
    console.error('Both DOMAINS_TO_AUTO_UPLOAD_IMAGES and DOMAINS_TO_AUTO_UPLOAD_IMAGES_EXCEPT are set. Please set only one of them.');
    process.exit(1);
}
if (domainsToAutoUploadImagesExcept.length === 0 && domainsToAutoUploadImages.length === 0) {
    console.warn('Neither DOMAINS_TO_AUTO_UPLOAD_IMAGES nor DOMAINS_TO_AUTO_UPLOAD_IMAGES_EXCEPT are set. The /auto-upload-images endpoint will be disabled.');
    autoUploadEnabled = false;
}

app.post('/auto-upload-images', async (req, res) => {
    if (!autoUploadEnabled) {
        return res.status(503).json({
            error: 'Auto-upload feature is disabled. Please configure DOMAINS_TO_AUTO_UPLOAD_IMAGES or DOMAINS_TO_AUTO_UPLOAD_IMAGES_EXCEPT environment variables.'
        });
    }

    const userInfo = getUserInfo(req);
    if (!userInfo) {
        return res.status(403).send({ok: false});
    }

    let code = req.body.code;
    if (!code) {
        return res.status(400).send({error: 'No code provided'});
    }

    if (typeof code === 'string') {
        code = [code];
    } else if (!Array.isArray(code)) {
        return res.status(400).send({error: 'Invalid code format'});
    }

    res.writeHead(200, {
        'Content-Type': 'application/json',
        'Transfer-Encoding': 'chunked'
    });

    try {
        const allImageUrls = code.flatMap(extractImageUrls);
        const filteredImageUrls = Array.from(new Set(allImageUrls.filter((url) => {
            const domain = new URL(url).hostname;

            if (domainsToAutoUploadImages.length > 0) {
                return domainsToAutoUploadImages.some(allowedDomain => domain.includes(allowedDomain));
            } else if (domainsToAutoUploadImagesExcept.length > 0) {
                return !domainsToAutoUploadImagesExcept.some(disallowedDomain => domain.includes(disallowedDomain));
            }
        })));

        const urlMap = new Map();
        const queue = new PQueue({concurrency: 5});

        let processedCount = 0;
        let successfulCount = 0;
        let failureCount = 0;
        let failureMessages = '';
        const totalUrls = filteredImageUrls.length;
        sendProgress(res, processedCount, totalUrls);

        await Promise.all(filteredImageUrls.map(url =>
            queue.add(async () => {
                if (imageUrlCache.has(url)) {
                    urlMap.set(url, imageUrlCache.get(url));
                    successfulCount++;
                    processedCount++;
                    sendProgress(res, processedCount, totalUrls);
                    return;
                }

                let attempts = 0;
                const maxAttempts = 3;
                const retryDelay = 1000;

                while (true) {
                    try {
                        const response = await axios.get(url, {
                            responseType: 'arraybuffer',
                            headers: {
                                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
                            }
                        });
                        const buffer = Buffer.from(response.data);

                        const filename = getFilenameFromUrl(url);
                        const {newUrl} = await processAndUploadFile(buffer, filename, userInfo);

                        urlMap.set(url, newUrl);
                        imageUrlCache.set(url, newUrl);
                        successfulCount++;
                        break;
                    } catch (error) {
                        attempts++;
                        if (attempts >= maxAttempts) {
                            failureCount++;
                            failureMessages += `${url}: ${error}\n`;
                            console.error(`Failed to process ${url} after ${maxAttempts} attempts`);
                            break;
                        } else {
                            console.warn(`Retrying ${url} (Attempt ${attempts}/${maxAttempts})`);
                            await new Promise((resolve) => setTimeout(resolve, retryDelay));
                        }
                    }
                }
                processedCount++;
                sendProgress(res, processedCount, totalUrls);
            })
        ));

        const updatedCodes = code.map(code => {
            let updatedCode = code;
            for (const [originalUrl, newUrl] of urlMap.entries()) {
                const regex = new RegExp(escapeRegExp(originalUrl), 'g');
                updatedCode = updatedCode.replace(regex, new URL(newUrl, process.env.APP_URL).href);
            }
            return updatedCode;
        });

        res.write(JSON.stringify({
            done: true,
            processedCount,
            successfulCount,
            failureCount,
            failureMessages,
            code: typeof req.body.code === 'string' ? updatedCodes[0] : updatedCodes
        }) + "\n");
        res.end();
    } catch (error) {
        console.error('Error processing images:', error);
        res.write(JSON.stringify({error: 'Error processing images'}) + "\n");
        res.end();
    }
});

function sendProgress(res, processed, total) {
    res.write(JSON.stringify({progress: {processed, total}}) + '\n');
}

function extractImageUrls(code) {
    const urls = new Set();

    // List of common image extensions
    const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'];

    // Regex to match URLs starting with http:// or https:// and ending with common image extensions
    const urlRegex = new RegExp(
        `https?:\\/\\/[^\\s'"\\[<]+?\\.(${imageExtensions.join('|')})(\\?[^\\s'"]*)?`,
        'gi'
    );

    let match;
    while ((match = urlRegex.exec(code)) !== null) {
        const url = match[0];
        urls.add(url);
    }

    return Array.from(urls);
}

function getFilenameFromUrl(url) {
    const pathname = new URL(url).pathname;
    return pathname.substring(pathname.lastIndexOf('/') + 1);
}

function escapeRegExp(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const MAIN_PORT = parseInt(process.env.MAIN_PORT || process.env.PORT || '3000');
app.listen(MAIN_PORT, () => {
    console.log(`Main server running on port ${MAIN_PORT}`);
});


async function decryptBuffer(encrypted, iv) {
    // Derive key from pre-shared secret
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        Buffer.from("fDfl4koWS3GR"),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: Buffer.from('salt'),
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encrypted
    );

    return Buffer.from(decrypted);
}