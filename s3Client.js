import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';

const endpoint = process.env.S3_ENDPOINT;
const fullEndpoint = endpoint.startsWith('http') ? endpoint : `https://${endpoint}`;

const s3Client = new S3Client({
    endpoint: fullEndpoint,
    region: process.env.S3_REGION,
    credentials: {
        accessKeyId: process.env.S3_ACCESS_KEY,
        secretAccessKey: process.env.S3_SECRET_KEY,
    },
    forcePathStyle: true,
    checksumAlgorithm: null,
    computeChecksums: false
});

const bucketName = process.env.S3_BUCKET;

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
        return await response.Body.transformToByteArray();
    } catch (err) {
        console.error('Error getting file:', err);
        throw err;
    }
}

export { uploadFile, getFile };
