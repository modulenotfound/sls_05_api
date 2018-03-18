const jwt = require('jsonwebtoken');

const user = {
  name: 'user',
  pwd: 'init'
};
const secret = 'BB9E.qcc$m&pYgWa62';

export const getToken = (event, context, callback) => {
  //get user name and password
  const body = JSON.parse(event.body);
  if (!body || user.name !== body.name || user.pwd !== body.pwd) {
    return callback(null, {
      statusCode: 400,
      body: JSON.stringify({
        message: 'wrong credentials'
      })
    });
  }

  //generate token
  const token = jwt.sign({
    name: body.name
  }, secret, { expiresIn: '1h' });

  return callback(null, {
    statusCode: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": true
    },
    body: JSON.stringify({
      token: token
    })
  });
};

export const auth = (event, context, callback) => {
  if (!event.authorizationToken) {
    return callback('Unauthorized');
  }

  try {
    const decoded = jwt.verify(event.authorizationToken, secret);
    return callback(null, generatePolicy(decoded.name, 'Allow', event.methodArn));
  } catch(e) {
    return callback('Unauthorized');
  }
}

export const getUsers = (event, context, callback) => {
  return callback(null, {
    statusCode: 200,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Credentials": true
    },
    body: JSON.stringify({
      message: 'you are ' + event.requestContext.authorizer.principalId
    })
  });
}


const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
}