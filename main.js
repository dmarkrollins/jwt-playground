const nJwt = require('njwt');
const secureRandom = require('secure-random')
const { v4: uuidv4 } = require('uuid')

const generateToken = ({ capabilityId, lob, deploymentId, env }) => {
    const signingKey = secureRandom(256, { type: 'Buffer' }); // Create a highly random byte array of 256 bytes

    const claims = {
        iss: "my.service.url",
        sub: capabilityId,
        scope: {
            deploymentInstanceId: deploymentId,
            lineOfBusiness: lob,
            targetEnvironment: env
        }
    }

    const jwt = nJwt.create(claims, signingKey);

    jwt.setExpiration(new Date().getTime() + (60 * 60 * 1000)) // 1 hour

    console.log('\n\nInitial raw JWT----------------------------------\n', jwt)

    const tokenId = jwt.body.jti

    const token = jwt.compact();

    return { signingKey, token, tokenId }
}

const verifyToken = ({ token, signingKey }) => {
    return nJwt.verify(token, signingKey);
}

const response = generateToken({ lob: 'fakeLOB', deploymentId: uuidv4(), env: 'fakeEnv', capabilityId: uuidv4() })

console.log('\n\nUniqueTokenId ---------------------------------\n', response.tokenId);
console.log('\nThe Token -------------------------------------\n', response.token);
console.log('\nThe Signing Key-------------------------------\n', response.signingKey);

const verifiedJwt = verifyToken({ token: response.token, signingKey: response.signingKey })

console.log('\n\nResult raw JWT----------------------------------\n', verifiedJwt)

console.log(verifiedJwt.toString())