const functions = require("firebase-functions");
const admin = require("firebase-admin");
const serviceAccount = require("./credential/fir-demo-integration-firebase-adminsdk-1xfzn-ceccae145e.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://fir-demo-integration.firebaseio.com"
});

const handleExistingUser = async (user, claim) => {
  let lastSignInTime = Date.parse(user.metadata.lastSignInTime) / 1000;
  let tokenIssuedTime = claim.iat;
  if (tokenIssuedTime <= lastSignInTime) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "This DID token is invalid."
    );
  }
  let uid = user.uid;
  let firebaseToken = await admin.auth().createCustomToken(user.uid);
  return {
    uid,
    token: firebaseToken
  };
};

const handleLegacyUser = async user => {
  let firebaseToken = await admin.auth().createCustomToken(user.uid);
  return {
    uid: user.uid,
    token: firebaseToken
  };
};

const handleNewUser = async (userId, email) => {
  await admin.auth().createUser({
    uid: userId,
    email: email,
    emailVerified: true
  });
  let firebaseToken = await admin.auth().createCustomToken(userId);
  return {
    uid: userId,
    token: firebaseToken
  };
};

exports.auth = functions.https.onCall(async (data, context) => {
  const { Magic } = require("@magic-sdk/admin");
  const magic = new Magic();
  const didToken = data.didToken;
  const email = data.email;
  const claim = magic.token.decode(didToken)[1];
  const userId = magic.token.getIssuer(didToken);
  try {
    /* If user is a DID-based user, check for replay attack (https://go.magic.link/replay-attack) */
    let user = (await admin.auth().getUser(userId)).toJSON();
    return await handleExistingUser(user, claim);
  } catch (err) {
    if (err.code === "auth/user-not-found") {
      try {
        /* Compatibility with legacy Firebase user */
        let legacyFirebaseUser = (await admin
          .auth()
          .getUserByEmail(email)).toJSON();
        return await handleLegacyUser(legacyFirebaseUser);
      } catch (err) {
        if (err.code === "auth/user-not-found") {
          /* Create new user */
          return await handleNewUser(userId, email);
        } else {
          throw err;
        }
      }
    } else {
      throw err;
    }
  }
});
