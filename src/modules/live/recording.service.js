const crypto = require('crypto');
const {
    EgressClient, EgressStatus, EncodedFileOutput, EncodedFileType, EncodingOptionsPreset, S3Upload
} = require('livekit-server-sdk');

// Cloud recording storage: any S3-compatible bucket. Cloudflare R2 is the intended one (no fees for
// students watching). Railway needs RECORDING_S3_ENDPOINT (https://<account-id>.r2.cloudflarestorage.com),
// RECORDING_S3_BUCKET, RECORDING_S3_ACCESS_KEY and RECORDING_S3_SECRET; RECORDING_S3_REGION defaults
// to "auto" (R2). Without them the Record button is hidden.
const getRecordingConfig = () => {
    const endpoint = (process.env.RECORDING_S3_ENDPOINT || '').trim().replace(/\/+$/, '');
    const bucket = process.env.RECORDING_S3_BUCKET;
    const accessKey = process.env.RECORDING_S3_ACCESS_KEY;
    const secret = process.env.RECORDING_S3_SECRET;
    if (!endpoint || !bucket || !accessKey || !secret) return null;
    return {
        endpoint: /^https?:\/\//.test(endpoint) ? endpoint : `https://${endpoint}`,
        bucket,
        accessKey,
        secret,
        region: process.env.RECORDING_S3_REGION || 'auto'
    };
};

let egressClient = null;
const getEgressClient = (config) => {
    if (!egressClient) egressClient = new EgressClient(config.httpUrl, config.apiKey, config.apiSecret);
    return egressClient;
};

// Records the whole meeting (speaker layout, screen share first) as a 720p MP4 uploaded to the bucket.
const startRoomRecording = (config, storage, roomName, fileKey) => {
    const file = new EncodedFileOutput({
        fileType: EncodedFileType.MP4,
        filepath: fileKey,
        output: {
            case: 's3',
            value: new S3Upload({
                accessKey: storage.accessKey,
                secret: storage.secret,
                bucket: storage.bucket,
                region: storage.region,
                endpoint: storage.endpoint,
                forcePathStyle: true
            })
        }
    });
    return getEgressClient(config).startRoomCompositeEgress(roomName, file, {
        layout: 'speaker',
        encodingOptions: EncodingOptionsPreset.H264_720P_30
    });
};

const stopRoomRecording = (config, egressId) => getEgressClient(config).stopEgress(egressId);

const getEgressInfo = async (config, egressId) => {
    const list = await getEgressClient(config).listEgress({ egressId });
    return list[0] || null;
};

// Maps a LiveKit egress to our recording status. A recording that hit LiveKit's time limit still has
// its file, so it counts as ready.
const egressOutcome = (info) => {
    const file = (info.fileResults && info.fileResults[0]) || null;
    const fileFields = file ? {
        duration: Math.round(Number(file.duration || 0) / 1e9),
        size: Number(file.size || 0)
    } : {};
    switch (info.status) {
        case EgressStatus.EGRESS_COMPLETE:
            return { status: 'ready', ...fileFields };
        case EgressStatus.EGRESS_LIMIT_REACHED:
            return file && Number(file.size) > 0 ? { status: 'ready', ...fileFields } : { status: 'failed', error: info.error || 'Recording limit reached' };
        case EgressStatus.EGRESS_FAILED:
        case EgressStatus.EGRESS_ABORTED:
            return { status: 'failed', error: info.error || 'Recording failed' };
        case EgressStatus.EGRESS_ENDING:
            return { status: 'processing' };
        default:
            return { status: 'recording' };
    }
};

// ---- S3 signing (AWS Signature V4, query-string form) ------------------------------------------
// Recordings stay private in the bucket; the API hands course members short-lived signed links.

const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const encodeRfc3986 = (str) => encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

const presignUrl = ({ method, origin, path, accessKey, secret, region, expires, query = {}, now = new Date() }) => {
    const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
    const date = amzDate.slice(0, 8);
    const scope = `${date}/${region}/s3/aws4_request`;
    const host = new URL(origin).host;
    const params = {
        ...query,
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        'X-Amz-Credential': `${accessKey}/${scope}`,
        'X-Amz-Date': amzDate,
        'X-Amz-Expires': String(expires),
        'X-Amz-SignedHeaders': 'host'
    };
    const canonicalQuery = Object.keys(params).sort()
        .map((k) => `${encodeRfc3986(k)}=${encodeRfc3986(params[k])}`)
        .join('&');
    const canonicalPath = path.split('/').map(encodeRfc3986).join('/');
    const canonicalRequest = [method, canonicalPath, canonicalQuery, `host:${host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
    const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
    const signingKey = hmac(hmac(hmac(hmac(`AWS4${secret}`, date), region), 's3'), 'aws4_request');
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
    return `${origin}${canonicalPath}?${canonicalQuery}&X-Amz-Signature=${signature}`;
};

const objectUrl = (storage, method, key, { expires = 3 * 3600, query } = {}) => presignUrl({
    method,
    origin: storage.endpoint,
    path: `/${storage.bucket}/${key}`,
    accessKey: storage.accessKey,
    secret: storage.secret,
    region: storage.region,
    expires,
    query
});

const playUrl = (storage, key) => objectUrl(storage, 'GET', key);
// filename* carries non-English (e.g. Arabic) course names; filename is the plain ASCII fallback.
const downloadUrl = (storage, key, filename) => {
    const ascii = filename.replace(/[^\x20-\x7e]+/g, '').replace(/["\\]/g, '').replace(/\s+/g, ' ').trim() || 'LiveClass.mp4';
    return objectUrl(storage, 'GET', key, {
        query: { 'response-content-disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeRfc3986(filename)}` }
    });
};

const deleteObject = async (storage, key) => {
    const res = await fetch(objectUrl(storage, 'DELETE', key, { expires: 300 }), { method: 'DELETE' });
    if (!res.ok && res.status !== 404) throw new Error(`Storage answered ${res.status}`);
};

module.exports = {
    getRecordingConfig,
    startRoomRecording,
    stopRoomRecording,
    getEgressInfo,
    egressOutcome,
    presignUrl,
    playUrl,
    downloadUrl,
    deleteObject
};
