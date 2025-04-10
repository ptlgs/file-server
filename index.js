import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
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
        throw error;
    }
}

const fileCache = new DiskStore({
    path: 'diskcache',
    ttl: 86400 * 3 * 1000,
    zip: false,
});

const hitCounter = new Map();

const app = express();

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({extended: true}));

// Set up multer with file size limit
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 500 * 1024 * 1024 // 500MB in bytes
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

        if (encryptedBuffer.length > 500 * 1024 * 1024) {
            return res.status(400).json({error: 'File size exceeds the 500MB limit'});
        }

        // Extract IV and encrypted data
        const iv = encryptedBuffer.slice(0, 16);
        const encrypted = encryptedBuffer.slice(16);

        // Decrypt using pre-shared key
        const decrypted = await decryptBuffer(encrypted, iv);

        const filename = req.headers['x-filename'] || '______';
        const {newUrl} = await processAndUploadFile(decrypted, filename, userInfo);

        res.json({url: newUrl});
    } catch (error) {
        console.error('Error uploading file:', error);
        res.status(500).json({error: 'Error uploading file'});
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

        if (hitCounter.get(key) >= 8 && fileData.length <= 500 * 1024 * 1024) {
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