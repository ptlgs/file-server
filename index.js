import express from 'express';
import multer from 'multer';
import crypto from 'crypto';
import fs from 'fs/promises';
import {createReadStream, mkdirSync} from 'fs';
import os from 'os';
import path from 'path';
import axios from 'axios';
import {HttpsProxyAgent} from 'https-proxy-agent';
import {getFile, uploadFile} from './s3Client.js';
import {decrypt, encrypt} from './encryption.js';
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

const CACHE_DIR = path.resolve(process.env.CACHE_DIR || 'diskcache');
const CACHE_MAX_USAGE_RATIO = parseRatioEnv('CACHE_MAX_USAGE_RATIO', 0.9);
const CONFIGURED_CACHE_MAX_BYTES = parseByteSizeEnv('CACHE_MAX_BYTES');
const CONFIGURED_CACHE_MIN_FREE_BYTES = parseByteSizeEnv('CACHE_MIN_FREE_BYTES');
let cacheMaxBytes = CONFIGURED_CACHE_MAX_BYTES;
let cacheUsageBytes = 0;
let cacheCleanupPromise = Promise.resolve();

mkdirSync(CACHE_DIR, {recursive: true});

const MAX_FILE_SIZE = parseInt(process.env.MAX_UPLOAD_BYTES || `${500 * 1024 * 1024}`, 10);
const MAX_UPLOAD_CHUNK_SIZE = parseInt(process.env.MAX_UPLOAD_CHUNK_BYTES || `${8 * 1024 * 1024}`, 10);
const MAX_ENCRYPTED_CHUNK_SIZE = MAX_UPLOAD_CHUNK_SIZE + 1024 * 1024;
const CHUNK_UPLOAD_TTL_MS = parseInt(process.env.CHUNK_UPLOAD_TTL_MS || `${24 * 60 * 60 * 1000}`, 10);
const chunkUploadRoot = path.resolve(process.env.UPLOAD_TMP_DIR || path.join(os.tmpdir(), 'file-server-chunk-uploads'));
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_FILE_KEY_LENGTH = 12;
const BASE58_FILE_KEY_SPACE = BigInt(BASE58_ALPHABET.length) ** BigInt(BASE58_FILE_KEY_LENGTH);

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

function getFileKey(sha256) {
    let value = BigInt(`0x${sha256}`) % BASE58_FILE_KEY_SPACE;
    let fileKey = '';

    for (let i = 0; i < BASE58_FILE_KEY_LENGTH; i++) {
        const index = Number(value % BigInt(BASE58_ALPHABET.length));
        fileKey = BASE58_ALPHABET[index] + fileKey;
        value = value / BigInt(BASE58_ALPHABET.length);
    }

    return fileKey;
}

function getCompletedFileKey(completed) {
    if (completed.fileKey) {
        return completed.fileKey;
    }
    if (completed.newUrl) {
        return completed.newUrl.split('/').filter(Boolean)[0];
    }
    return undefined;
}

function parseRatioEnv(name, fallback) {
    const value = process.env[name];
    if (!value) {
        return fallback;
    }

    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed) && parsed > 0 && parsed <= 1) {
        return parsed;
    }

    console.warn(`Invalid ${name} value "${value}", using ${fallback}`);
    return fallback;
}

function parseByteSizeEnv(name) {
    const value = process.env[name];
    if (!value) {
        return undefined;
    }

    const match = value.trim().match(/^(\d+(?:\.\d+)?)\s*(b|k|kb|ki|kib|m|mb|mi|mib|g|gb|gi|gib|t|tb|ti|tib)?$/i);
    if (!match) {
        console.warn(`Invalid ${name} value "${value}", ignoring it`);
        return undefined;
    }

    const units = {
        b: 1,
        k: 1024,
        kb: 1024,
        ki: 1024,
        kib: 1024,
        m: 1024 ** 2,
        mb: 1024 ** 2,
        mi: 1024 ** 2,
        mib: 1024 ** 2,
        g: 1024 ** 3,
        gb: 1024 ** 3,
        gi: 1024 ** 3,
        gib: 1024 ** 3,
        t: 1024 ** 4,
        tb: 1024 ** 4,
        ti: 1024 ** 4,
        tib: 1024 ** 4,
    };
    const unit = (match[2] || 'b').toLowerCase();
    return Math.floor(Number.parseFloat(match[1]) * units[unit]);
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes)) {
        return 'unknown';
    }

    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let value = bytes;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
        value /= 1024;
        unitIndex++;
    }

    return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function resolveCacheMaxBytes(totalBytes) {
    if (CONFIGURED_CACHE_MAX_BYTES !== undefined) {
        return CONFIGURED_CACHE_MAX_BYTES;
    }

    return Math.floor(totalBytes * CACHE_MAX_USAGE_RATIO);
}

function getCacheMaxBytesSource() {
    if (CONFIGURED_CACHE_MAX_BYTES !== undefined) {
        return 'CACHE_MAX_BYTES';
    }

    return `detected filesystem * ${CACHE_MAX_USAGE_RATIO}`;
}

function resolveCacheMinFreeBytes(totalBytes) {
    if (CONFIGURED_CACHE_MIN_FREE_BYTES !== undefined) {
        return CONFIGURED_CACHE_MIN_FREE_BYTES;
    }

    return Math.floor(Math.min(1024 ** 3, Math.max(128 * 1024 ** 2, totalBytes * 0.1)));
}

function getCacheEntryBaseByKey(key) {
    const hash = crypto.createHash('md5').update(`${key}`).digest('hex');
    return path.join(CACHE_DIR, `filecache-${hash.substring(0, 3)}`, hash.substring(3));
}

function getCacheEntryInfoByFilePath(filePath) {
    const dir = path.dirname(filePath);
    const dirName = path.basename(dir);
    const fileName = path.basename(filePath);

    if (/^filecache-[0-9a-f]{3}$/i.test(dirName)) {
        if (fileName.endsWith('.json')) {
            return {
                basePath: path.join(dir, fileName.slice(0, -'.json'.length)),
                format: 'raw',
            };
        }

        if (fileName.endsWith('.bin')) {
            return {
                basePath: path.join(dir, fileName.slice(0, -'.bin'.length)),
                format: 'raw',
            };
        }

        return null;
    }

    if (/^diskstore-[0-9a-f]{3}$/i.test(dirName)) {
        if (fileName.endsWith('.json')) {
            return {
                basePath: path.join(dir, fileName.slice(0, -'.json'.length)),
                format: 'legacy-diskstore',
            };
        }

        const binMatch = fileName.match(/-\d+\.bin$/);
        if (binMatch) {
            return {
                basePath: path.join(dir, fileName.slice(0, -binMatch[0].length)),
                format: 'legacy-diskstore',
            };
        }
    }

    return null;
}

function getCacheDataPath(basePath) {
    return `${basePath}.bin`;
}

function getCacheMetadataPath(basePath) {
    return `${basePath}.json`;
}

function estimateCacheEntryBytes(dataLength) {
    return dataLength + 16 * 1024;
}

function isNoSpaceError(error) {
    return error && (error.code === 'ENOSPC' || error.code === 'EDQUOT');
}

async function getCacheFilesystemStats() {
    await fs.mkdir(CACHE_DIR, {recursive: true});
    const stats = await fs.statfs(CACHE_DIR);
    const blockSize = stats.bsize || 1;

    return {
        totalBytes: stats.blocks * blockSize,
        freeBytes: stats.bfree * blockSize,
        availableBytes: stats.bavail * blockSize,
    };
}

async function walkCacheFiles(dir, visitFile) {
    let entries;
    try {
        entries = await fs.readdir(dir, {withFileTypes: true});
    } catch (error) {
        if (error.code === 'ENOENT') {
            return;
        }
        throw error;
    }

    await Promise.all(entries.map(async (entry) => {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            await walkCacheFiles(fullPath, visitFile);
            return;
        }

        if (entry.isFile()) {
            await visitFile(fullPath);
        }
    }));
}

async function collectCacheEntries() {
    const entriesByBase = new Map();

    await walkCacheFiles(CACHE_DIR, async (filePath) => {
        const cacheEntryInfo = getCacheEntryInfoByFilePath(filePath);
        if (!cacheEntryInfo) {
            return;
        }

        const {basePath, format} = cacheEntryInfo;
        const stat = await fs.stat(filePath);
        const entry = entriesByBase.get(basePath) || {
            basePath,
            format,
            files: [],
            size: 0,
            lastAccessedMs: 0,
            key: null,
        };

        entry.files.push(filePath);
        entry.size += stat.size;
        entry.lastAccessedMs = Math.max(entry.lastAccessedMs, stat.mtimeMs);

        if (filePath.endsWith('.json')) {
            try {
                const data = JSON.parse(await fs.readFile(filePath, 'utf8'));
                entry.key = data.key;
            } catch (error) {
                console.warn(`Failed to read cache metadata ${filePath}:`, error.message);
            }
        }

        entriesByBase.set(basePath, entry);
    });

    return Array.from(entriesByBase.values());
}

async function deleteCacheEntry(entry) {
    await Promise.all(entry.files.map(filePath => fs.rm(filePath, {force: true})));
    await fs.rmdir(path.dirname(entry.basePath)).catch(() => 0);
}

async function evictCacheEntries(entries, bytesToFree, reason) {
    let freedBytes = 0;
    let evictedCount = 0;

    entries.sort((a, b) => a.lastAccessedMs - b.lastAccessedMs);

    for (const entry of entries) {
        if (freedBytes >= bytesToFree) {
            break;
        }

        try {
            await deleteCacheEntry(entry);
            freedBytes += entry.size;
            evictedCount++;
        } catch (error) {
            console.warn(`Failed to evict cache entry ${entry.key || entry.basePath}:`, error.message);
        }
    }

    if (evictedCount > 0) {
        console.log(`File cache LRU evicted ${evictedCount} entries, freed about ${formatBytes(freedBytes)} (${reason})`);
    }

    return freedBytes;
}

async function enforceCacheLimits(requiredBytes = 0, reason = 'cache limit') {
    const stats = await getCacheFilesystemStats();
    cacheMaxBytes = resolveCacheMaxBytes(stats.totalBytes);
    const minFreeBytes = resolveCacheMinFreeBytes(stats.totalBytes);
    let entries = await collectCacheEntries();
    let usageBytes = entries.reduce((sum, entry) => sum + entry.size, 0);
    let freedBytes = 0;

    const expectedAvailableBytes = stats.availableBytes + freedBytes;
    const maxSizeShortfall = Math.max(0, usageBytes + requiredBytes - cacheMaxBytes);
    const freeSpaceShortfall = Math.max(0, minFreeBytes + requiredBytes - expectedAvailableBytes);
    const bytesToFree = Math.max(maxSizeShortfall, freeSpaceShortfall);

    if (bytesToFree > 0) {
        const lruFreedBytes = await evictCacheEntries(entries, bytesToFree, reason);
        freedBytes += lruFreedBytes;
        usageBytes = Math.max(0, usageBytes - lruFreedBytes);
    }

    cacheUsageBytes = usageBytes;
    return {usageBytes, freedBytes, stats, minFreeBytes};
}

async function runCacheCleanup(requiredBytes = 0, reason = 'cache limit') {
    const cleanup = cacheCleanupPromise.then(() => enforceCacheLimits(requiredBytes, reason));
    cacheCleanupPromise = cleanup.catch(() => 0);
    return cleanup;
}

async function initializeFileCache() {
    try {
        const stats = await getCacheFilesystemStats();
        cacheMaxBytes = resolveCacheMaxBytes(stats.totalBytes);
        const minFreeBytes = resolveCacheMinFreeBytes(stats.totalBytes);

        console.log(`File cache directory: ${CACHE_DIR}`);
        console.log(`Detected file cache filesystem: total=${formatBytes(stats.totalBytes)}, available=${formatBytes(stats.availableBytes)}, free=${formatBytes(stats.freeBytes)}, max cache=${formatBytes(cacheMaxBytes)} (${getCacheMaxBytesSource()}), min free=${formatBytes(minFreeBytes)}`);

        const result = await runCacheCleanup(0, 'startup');
        console.log(`File cache startup usage: ${formatBytes(result.usageBytes)}`);
    } catch (error) {
        console.warn('Failed to initialize file cache limits:', error.message);
    }
}

async function touchCacheEntry(key) {
    const basePath = getCacheEntryBaseByKey(key);
    const now = new Date();

    await Promise.all([
        fs.utimes(getCacheDataPath(basePath), now, now).catch(() => 0),
        fs.utimes(getCacheMetadataPath(basePath), now, now).catch(() => 0),
    ]);
}

async function getCachedFileData(key) {
    const basePath = getCacheEntryBaseByKey(key);

    try {
        const metadata = JSON.parse(await fs.readFile(getCacheMetadataPath(basePath), 'utf8'));

        if (metadata.key !== key) {
            return undefined;
        }

        const cachedData = await fs.readFile(getCacheDataPath(basePath));
        await touchCacheEntry(key);
        return cachedData;
    } catch (error) {
        if (error.code === 'ENOENT') {
            return undefined;
        }

        console.warn(`Failed to read file cache for ${key}:`, error.message);
        return undefined;
    }
}

async function writeCacheEntry(key, fileData) {
    const basePath = getCacheEntryBaseByKey(key);
    const dir = path.dirname(basePath);
    const tempSuffix = `${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`;
    const tempDataPath = `${getCacheDataPath(basePath)}.${tempSuffix}`;
    const tempMetadataPath = `${getCacheMetadataPath(basePath)}.${tempSuffix}`;
    const metadata = {
        key,
        size: fileData.length,
    };

    await fs.mkdir(dir, {recursive: true});

    try {
        await fs.writeFile(tempDataPath, fileData);
        await fs.writeFile(tempMetadataPath, JSON.stringify(metadata));
        await fs.rename(tempDataPath, getCacheDataPath(basePath));
        await fs.rename(tempMetadataPath, getCacheMetadataPath(basePath));
    } catch (error) {
        await Promise.all([
            fs.rm(tempDataPath, {force: true}),
            fs.rm(tempMetadataPath, {force: true}),
        ]);
        throw error;
    }
}

async function cacheFileData(key, fileData) {
    const estimatedBytes = estimateCacheEntryBytes(fileData.length);

    if (cacheMaxBytes !== undefined && estimatedBytes > cacheMaxBytes) {
        console.warn(`Skipping cache for ${key}: file size ${formatBytes(fileData.length)} exceeds cache max ${formatBytes(cacheMaxBytes)}`);
        return;
    }

    try {
        const stats = await getCacheFilesystemStats();
        const minFreeBytes = resolveCacheMinFreeBytes(stats.totalBytes);
        const needsCleanup = stats.availableBytes - estimatedBytes < minFreeBytes ||
            (cacheMaxBytes !== undefined && cacheUsageBytes + estimatedBytes > cacheMaxBytes);

        if (needsCleanup) {
            await runCacheCleanup(estimatedBytes, 'making room for cache write');
        }

        await writeCacheEntry(key, fileData);
        cacheUsageBytes += estimatedBytes;
        await touchCacheEntry(key);
    } catch (error) {
        if (!isNoSpaceError(error)) {
            console.warn(`Failed to cache file ${key}:`, error.message);
            return;
        }

        try {
            console.warn(`Cache write for ${key} ran out of disk space; evicting LRU entries and retrying`);
            await runCacheCleanup(estimatedBytes, 'recovering from low disk space');
            await writeCacheEntry(key, fileData);
            cacheUsageBytes += estimatedBytes;
            await touchCacheEntry(key);
        } catch (retryError) {
            console.warn(`Failed to cache file ${key} after LRU eviction:`, retryError.message);
        }
    }
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

    const fileKey = getFileKey(sha256);
    const newUrl = `/${fileKey}/${meta.filename}`;

    try {
        await uploadFile(fileKey, createReadStream(encryptedTempPath), {
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

    return {sha256, fileKey, newUrl};
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
    const fileKey = getFileKey(sha256);
    const encryptedData = encrypt(buffer);

    await uploadFile(fileKey, encryptedData);

    const newUrl = `/${fileKey}/${originalFilename}`;

    await writeLogToElasticsearch({
        timestamp: new Date(),
        user_id: userInfo.userId,
        file_name: originalFilename,
        file_url: newUrl,
        file_size: buffer.length
    });

    return {sha256, fileKey, newUrl};
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
            const fileKey = getCompletedFileKey(completed);
            return res.json({
                ok: true,
                completed: true,
                url: completed.newUrl,
                fileKey,
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
            const fileKey = getCompletedFileKey(completed);
            return res.json({ok: true, completed: true, url: completed.newUrl, fileKey});
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
            const fileKey = getCompletedFileKey(completed);
            return res.json({
                url: completed.newUrl,
                sha256: completed.sha256,
                fileKey,
                completed: true
            });
        }

        const received = await getReceivedChunkIndexes(uploadDir, meta);
        if (received.length !== meta.totalChunks) {
            const receivedSet = new Set(received);
            const missing = Array.from({length: meta.totalChunks}, (_, i) => i).filter(i => !receivedSet.has(i));
            return res.status(409).json({error: 'Missing chunks', missing, received});
        }

        const {sha256, fileKey, newUrl} = await processAndUploadFileFromChunks(uploadDir, meta, userInfo);

        await fs.writeFile(path.join(uploadDir, 'completed.json'), JSON.stringify({
            sha256,
            fileKey,
            newUrl,
            completedAt: new Date().toISOString(),
        }, null, 2));
        await removeChunkFiles(uploadDir, meta);
        await fs.utimes(uploadDir, new Date(), new Date());

        res.json({url: newUrl, sha256, fileKey});
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

app.get('/:fileKey/:filename', async (req, res) => {
    try {
        const {fileKey, filename} = req.params;
        const key = fileKey;

        // Set aggressive caching headers
        res.set({
            'Cache-Control': 'public, max-age=31536000, immutable',
            'ETag': `"${fileKey}"`,
        });

        // Check if the file is in cache
        const cachedData = await getCachedFileData(key);
        if (cachedData) {
            res.contentType(filename);
            return res.send(cachedData);
        }

        const encryptedData = await getFile(key);
        let fileData = decrypt(encryptedData);
        await cacheFileData(key, fileData);

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
await initializeFileCache();
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
