import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const { HttpProxyAgent, HttpsProxyAgent } = require('hpagent');

const endpoint = process.env.S3_ENDPOINT;
const fullEndpoint = endpoint.startsWith('http') ? endpoint : `https://${endpoint}`;
const s3Proxy = process.env.S3_PROXY || process.env.PROXY;

function createS3RequestHandler() {
    if (!s3Proxy) {
        return undefined;
    }

    return new NodeHttpHandler({
        httpAgent: new HttpProxyAgent({proxy: s3Proxy}),
        httpsAgent: new HttpsProxyAgent({proxy: s3Proxy}),
    });
}

const s3Client = new S3Client({
    endpoint: fullEndpoint,
    region: process.env.S3_REGION,
    credentials: {
        accessKeyId: process.env.S3_ACCESS_KEY,
        secretAccessKey: process.env.S3_SECRET_KEY,
    },
    forcePathStyle: true,
    checksumAlgorithm: null,
    computeChecksums: false,
    requestHandler: createS3RequestHandler(),
});

const bucketName = process.env.S3_BUCKET;
const DOWNLOAD_PROGRESS_LOG_INTERVAL_MS = 1000;

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

function formatDuration(seconds) {
    if (!Number.isFinite(seconds)) {
        return 'unknown';
    }

    const roundedSeconds = Math.max(0, Math.round(seconds));
    const hours = Math.floor(roundedSeconds / 3600);
    const minutes = Math.floor((roundedSeconds % 3600) / 60);
    const remainingSeconds = roundedSeconds % 60;

    if (hours > 0) {
        return `${hours}h ${minutes}m ${remainingSeconds}s`;
    }

    if (minutes > 0) {
        return `${minutes}m ${remainingSeconds}s`;
    }

    return `${remainingSeconds}s`;
}

function createDownloadProgressLogger(key, totalBytes) {
    const startTime = Date.now();
    let downloadedBytes = 0;

    function logProgress(status = 'progress') {
        const elapsedSeconds = Math.max((Date.now() - startTime) / 1000, 0.001);
        const bytesPerSecond = downloadedBytes / elapsedSeconds;
        const hasTotal = Number.isSafeInteger(totalBytes) && totalBytes > 0;
        const progress = hasTotal ? `${Math.min(100, (downloadedBytes / totalBytes) * 100).toFixed(1)}%` : 'unknown';
        const etaSeconds = hasTotal && bytesPerSecond > 0 ? (totalBytes - downloadedBytes) / bytesPerSecond : Number.NaN;

        console.log(`S3 download ${status}: key=${key} progress=${progress} downloaded=${formatBytes(downloadedBytes)} total=${formatBytes(totalBytes)} ETA=${formatDuration(etaSeconds)}`);
    }

    const interval = setInterval(logProgress, DOWNLOAD_PROGRESS_LOG_INTERVAL_MS);
    interval.unref?.();

    return {
        addChunk(chunkLength) {
            downloadedBytes += chunkLength;
        },
        complete() {
            clearInterval(interval);
            logProgress('complete');
        },
        fail() {
            clearInterval(interval);
            logProgress('failed');
        },
    };
}

async function readBodyWithProgress(body, key, totalBytes) {
    const progressLogger = createDownloadProgressLogger(key, totalBytes);
    const chunks = [];

    try {
        for await (const chunk of body) {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            chunks.push(buffer);
            progressLogger.addChunk(buffer.length);
        }

        progressLogger.complete();
        return Buffer.concat(chunks);
    } catch (error) {
        progressLogger.fail();
        throw error;
    }
}

async function uploadFile(key, data, options = {}) {
    const putObjectInput = {
        Bucket: bucketName,
        Key: key,
        Body: data,
    };

    if (Number.isSafeInteger(options.contentLength)) {
        putObjectInput.ContentLength = options.contentLength;
    }

    const command = new PutObjectCommand(putObjectInput);

    try {
        const response = await s3Client.send(command);
        console.log(`File uploaded successfully. ETag: ${response.ETag}`);
        return response;
    } catch (err) {
        console.error('Error uploading file:', err);
        throw err;
    }
}

async function getFile(key) {
    const command = new GetObjectCommand({
        Bucket: bucketName,
        Key: key,
    });

    try {
        const response = await s3Client.send(command);
        return await readBodyWithProgress(response.Body, key, response.ContentLength);
    } catch (err) {
        console.error('Error getting file:', err);
        throw err;
    }
}

export { uploadFile, getFile };
