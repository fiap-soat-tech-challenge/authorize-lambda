const jwt = require("jsonwebtoken");

function generateAuthResponse(principalId, effect, methodArn) {
  const policyDocument = generatePolicyDocument(effect, methodArn);

  return {
    principalId,
    policyDocument
  };
}

function generatePolicyDocument(effect, methodArn) {
  if (!effect || !methodArn) return null;

  const policyDocument = {
    Version: '2012-10-17',
    Statement: [
      {
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: methodArn
      }
    ]
  };

  return policyDocument;
}

function extractTokenFromHeader(event) {
  if (event.authorizationToken && event.authorizationToken.split(' ')[0] === 'Bearer') {
    return event.authorizationToken.split(' ')[1];
  } else {
    return event.authorizationToken;
  }
}

exports.handler = (event, context, callback) => {
  const token = extractTokenFromHeader(event) || '';
  const methodArn = event.methodArn;

  if (!token || !methodArn) return callback(null, 'Unauthorized');

  const secret = Buffer.from(process.env.JWT_SECRET, 'base64');

  try {
    const decoded = jwt.verify(token, secret);

    if (decoded && decoded.cpf) {
      return callback(null, generateAuthResponse(decoded.cpf, 'Allow', methodArn));
    } else {
      return callback(null, generateAuthResponse('user', 'Deny', methodArn));
    }
  } catch (e) {
    return callback(null, 'Unauthorized');
  }
}
