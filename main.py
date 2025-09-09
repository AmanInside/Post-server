// index.js (CommonJS)
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fetch = require('node-fetch');

const PORT = process.env.PORT || 3000;
const APP_SECRET = process.env.FB_APP_SECRET;
const PAGE_ACCESS_TOKEN = process.env.FB_PAGE_ACCESS_TOKEN;
const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN;

if (!APP_SECRET || !PAGE_ACCESS_TOKEN || !VERIFY_TOKEN) {
  console.error('Missing FB environment variables. Set FB_APP_SECRET, FB_PAGE_ACCESS_TOKEN, FB_VERIFY_TOKEN');
  process.exit(1);
}

const app = express();
// Save raw body for signature verification
app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf.toString(); } }));

// webhook verification (GET)
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('WEBHOOK_VERIFIED');
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// signature verification middleware
function verifySignature(req, res, next) {
  const signature = req.headers['x-hub-signature-256'] || req.headers['x-hub-signature'];
  if (!signature) return res.sendStatus(400);
  const sigHash = signature.split('=')[1];
  const expectedHash = crypto.createHmac('sha256', APP_SECRET).update(req.rawBody).digest('hex');
  const bufA = Buffer.from(sigHash, 'hex');
  const bufB = Buffer.from(expectedHash, 'hex');
  if (bufA.length !== bufB.length || !crypto.timingSafeEqual(bufA, bufB)) {
    console.warn('Signature mismatch');
    return res.sendStatus(403);
  }
  next();
}

// message webhook (POST)
app.post('/webhook', verifySignature, async (req, res) => {
  const body = req.body;
  if (body.object === 'page') {
    for (const entry of body.entry) {
      for (const event of entry.messaging) {
        const senderId = event.sender.id;
        if (event.message) {
          await handleMessage(senderId, event.message);
        } else if (event.postback) {
          await handlePostback(senderId, event.postback);
        }
      }
    }
    res.status(200).send('EVENT_RECEIVED');
  } else {
    res.sendStatus(404);
  }
});

async function handleMessage(senderId, message) {
  const text = message.text || '';
  // simple echo logic — replace with your convo engine / LLM / rules
  const reply = { text: `Aapne likha: ${text}` };
  return callSendAPI(senderId, reply);
}

async function handlePostback(senderId, postback) {
  const payload = postback.payload;
  return callSendAPI(senderId, { text: `Postback received: ${payload}` });
}

async function callSendAPI(recipientId, message) {
  const url = `https://graph.facebook.com/v16.0/me/messages?access_token=${PAGE_ACCESS_TOKEN}`;
  const body = { recipient: { id: recipientId }, message };
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    console.error('Send API error', await res.text());
  }
}

app.listen(PORT, () => console.log(`Server listening on ${PORT}`));