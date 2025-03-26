const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const path = require('path');
const { GoogleGenAI } = require('@google/genai');

let chatsCollection;

dotenv.config();
const SECRET = process.env.SECRET || 'super-mega-secret-key';
const SERVER_PORT = process.env.PORT || 8080;
const MONGO_USER = process.env.MONGO_INITDB_ROOT_USERNAME || "administrator";
const MONGO_PASS = process.env.MONGO_INITDB_ROOT_PASSWORD || "password";
const MONGO_HOST = process.env.MONGO_HOST || "database";
const MONGO_DB = process.env.MONGO_INITDB_DATABASE || "sessions";
const MONGO_URI = `mongodb://${MONGO_USER}:${MONGO_PASS}@${MONGO_HOST}:27017/${MONGO_DB}?authSource=admin`;
const MAX_MESSAGE_LENGTH = parseInt(process.env.MAX_MESSAGE_LENGTH) || 500;
const RATE_LIMITER_SECONDS = process.env.RATE_LIMITER_SECONDS || 5;
const SYSTEM_MESSAGE = process.env.SYSTEM_MESSAGE;

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
});
const config = {
  responseMimeType: 'text/plain',
};
const model = 'gemini-2.0-flash-lite';

const app = express();

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'templates'));

app.use(session({
  secret: SECRET,
  resave: true,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    autoRemove: 'native',
    collectionName: 'sessions',
    ttl: 2 * 60 * 60, // 2 hours
    crypto: {
      secret: SECRET,
    },
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    path: '/',
    maxAge: 1000 * 60 * 60 * 2, // 2 hours,
    sameSite: 'strict',
  }
}))

async function limiter(req, res, next) {
  if (!req.session.last_request || req.session.last_request < Date.now() - 1000 * RATE_LIMITER_SECONDS) {
    req.session.last_request = Date.now();
    req.session.save();
    next();
  } else {
    req.session.last_request = Date.now();
    req.session.save();
    return res.status(429).send(`Too many requests, please try again in ${RATE_LIMITER_SECONDS} seconds.`);
  }
}

async function hasRequestStillPending(req, res, next) {
  if (req.session.pending_response === true) {
    return res.status(429).send('You already have a request in progress, please wait for it to finish.');
  } else {
    next();
  }
}

function setupSession(req, res, next) {
  if (!req.session.context) {
    req.session.context = [];
  }
  next();
}

app.get('/', setupSession, async function (req, res) {
  messages = req.session.context.map(msg => ({ is_user: msg.role === 'user', text: msg.parts[0].text }));
  res.render('chat', { messages });
});

app.post('/api/send', limiter, hasRequestStillPending, async function (req, res) {
  let message = req.body.message;
  if (!message || typeof message !== 'string') {
    return res.status(400).send('Invalid message');
  }

  message = message.trim();
  if (message.length === 0) {
    return res.status(400).send('Message cannot be empty');
  }

  if (message.length > MAX_MESSAGE_LENGTH) {
    return res.status(400).send('Message too long');
  }

  req.session.pending_response = true;
  req.session.save();

  let context = req.session.context;
  while (context.length > 8) {
    context.shift();
  }

  context = [
    {
      role: 'user',
      parts: [
        {
          text: SYSTEM_MESSAGE,
        },
      ],
    },
    {
      role: 'model',
      parts: [
        {
          text: 'I understand, I will obey your instructions.',
        },
      ],
    }
  ].concat(context);

  const contents = [
    ...context,
    {
      role: 'user',
      parts: [
        {
          text: message,
        },
      ],
    },
  ];

  let ai_answer = '';

  try {
    const response = await ai.models.generateContentStream({
      model,
      config,
      contents,
    });


    for await (const chunk of response) {
      if (chunk && chunk.text) {
        ai_answer += chunk.text;
      }
    }
  } catch (error) {
    req.session.pending_response = false;
    req.session.save();
    console.error('Error generating AI response:', error);
    return res.status(500).send('Internal server error');
  }

  req.session.context.push({
    role: 'user',
    parts: [
      {
        text: message,
      },
    ],
  });

  req.session.context.push({
    role: 'model',
    parts: [
      {
        text: ai_answer,
      },
    ],
  });

  try {
    await chatsCollection.insertOne({
      sessionId: req.sessionID,
      timestamp: new Date(),
      userMessage: message,
      aiResponse: ai_answer
    });
  } catch (err) {
    console.error('Failed to save chat to collection:', err);
  }

  req.session.pending_response = false;
  res.json({ answer: ai_answer });
});

const mongoClient = new MongoClient(MONGO_URI);
mongoClient.connect().then(() => {
  chatsCollection = mongoClient.db().collection('chats');
  console.log('Connected to MongoDB for chats collection');

  app.listen(SERVER_PORT, () => {
    console.log(`Server is up on http://localhost:${SERVER_PORT}`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});