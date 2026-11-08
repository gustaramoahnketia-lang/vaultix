// One step of an "update" simulation. Each call is a fresh process, the way the
// app starts again after an update. Usage: node account-step.mjs register|login email password
import '../../server/keys.js';
import { createUser, verifyLoginAndUnlock } from '../../server/auth.js';
const [action, email, password] = process.argv.slice(2);
try {
  if (action === 'register') {
    createUser({ name: 'Update Test', email, password, recoveryEmail: email });
    console.log('registered');
  } else {
    const { user } = verifyLoginAndUnlock({ email, password, device: 'test', ip: 'test' });
    console.log('signed in as ' + user.email);
  }
} catch (err) {
  console.error('FAILED: ' + err.message);
  process.exit(1);
}
