import jwt from 'jsonwebtoken';

function generateToken() {
    const payload = {
        iat: Math.floor(Date.now() / 1000),
        userId: 1
    };

    const options = {
        expiresIn: '3600s',
    };

    try {
        return jwt.sign(payload, process.env.JWT_SECRET, options);
    } catch (error) {
        console.error('Error generating token:', error.message);
        return null;
    }
}

if (import.meta.url === import.meta.resolve(process.argv[1])) {
    console.log(generateToken());
}

export { generateToken };
