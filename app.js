const mongoose = require("mongoose");
const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const app = express();
const server = http.createServer(app);

// ✅ Fixed: Socket.IO CORS config
const io = require('socket.io')(server, {
  cors: {
    origin: 'https://chatappfrontend-pi.vercel.app',
    methods: ["GET", "POST"],
    credentials: true
  }
});

// ✅ Fixed: Express CORS config
app.use(cors({
  origin: 'https://chatappfrontend-pi.vercel.app',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// DB Connection
require('./db/connection');

// Import Models
const Users = require('./models/Users');
const Conversations = require('./models/Conversations');
const Messages = require('./models/Messages');

// 🔌 Socket.IO Logic
let users = [];

io.on('connection', socket => {
  console.log('User connected', socket.id);

  socket.on('addUser', userId => {
    const isUserExist = users.find(user => user.userId === userId);
    if (!isUserExist) {
      const user = { userId, socketId: socket.id };
      users.push(user);
      io.emit('getUsers', users);
    }
  });

  socket.on('sendMessage', async ({ senderId, receiverId, message, conversationId }) => {
    const receiver = users.find(user => user.userId === receiverId);
    const sender = users.find(user => user.userId === senderId);
    const user = await Users.findById(senderId);

    const messageData = {
      senderId,
      message,
      conversationId,
      receiverId,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email
      }
    };

    if (receiver) {
      io.to(receiver.socketId).to(sender.socketId).emit('getMessage', messageData);
    } else {
      io.to(sender.socketId).emit('getMessage', messageData);
    }
  });

  socket.on('disconnect', () => {
    users = users.filter(user => user.socketId !== socket.id);
    io.emit('getUsers', users);
  });
});

// Routes
app.get('/', (req, res) => {
  res.send('Welcome');
});

// Register Route
app.post('/api/register', async (req, res, next) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).send('Please fill all required fields');
    }

    const isAlreadyExist = await Users.findOne({ email });
    if (isAlreadyExist) {
      return res.status(400).send('User already exists');
    }

    const newUser = new Users({ fullName, email });
    bcryptjs.hash(password, 10, (err, hashedPassword) => {
      newUser.set('password', hashedPassword);
      newUser.save();
      next();
    });

    return res.status(200).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send('Internal server error');
  }
});

// Login Route
app.post('/api/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).send('Please fill all required fields');
    }

    const user = await Users.findOne({ email });
    if (!user) {
      return res.status(400).send('User email or password is incorrect');
    }

    const validateUser = await bcryptjs.compare(password, user.password);
    if (!validateUser) {
      return res.status(400).send('User email or password is incorrect');
    }

    const payload = {
      userId: user._id,
      email: user.email
    };

    const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY || 'THIS_IS_A_JWT_SECRET_KEY';

    jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: 84600 }, async (err, token) => {
      await Users.updateOne({ _id: user._id }, {
        $set: { token }
      });

      user.save();
      return res.status(200).json({
        user: {
          id: user._id,
          email: user.email,
          fullName: user.fullName
        },
        token
      });
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Internal server error');
  }
});

// Create Conversation
app.post('/api/conversation', async (req, res) => {
  try {
    const { senderId, receiverId } = req.body;
    const newConversation = new Conversations({ members: [senderId, receiverId] });
    await newConversation.save();
    res.status(200).send('Conversation created successfully');
  } catch (error) {
    console.error('Conversation error:', error);
    res.status(500).send('Internal server error');
  }
});

// Get Conversations for a User
app.get('/api/conversations/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const conversations = await Conversations.find({ members: { $in: [userId] } });

    const conversationUserData = Promise.all(conversations.map(async (conversation) => {
      const receiverId = conversation.members.find((member) => member !== userId);
      const user = await Users.findById(receiverId);
      return {
        user: {
          receiverId: user._id,
          email: user.email,
          fullName: user.fullName
        },
        conversationId: conversation._id
      };
    }));

    res.status(200).json(await conversationUserData);
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).send('Internal server error');
  }
});

// Send Message
app.post('/api/message', async (req, res) => {
  try {
    const { conversationId, senderId, message, receiverId = '' } = req.body;

    if (!senderId || !message) return res.status(400).send('Please fill all required fields');

    if (conversationId === 'new' && receiverId) {
      const newConversation = new Conversations({ members: [senderId, receiverId] });
      await newConversation.save();

      const newMessage = new Messages({
        conversationId: newConversation._id,
        senderId,
        message
      });

      await newMessage.save();
      return res.status(200).send('Message sent successfully');
    }

    if (!conversationId) {
      return res.status(400).send('Please fill all required fields');
    }

    const newMessage = new Messages({ conversationId, senderId, message });
    await newMessage.save();

    res.status(200).send('Message sent successfully');
  } catch (error) {
    console.error('Message error:', error);
    res.status(500).send('Internal server error');
  }
});

// Get Messages
app.get('/api/message/:conversationId', async (req, res) => {
  try {
    const checkMessages = async (conversationId) => {
      const messages = await Messages.find({ conversationId });
      const messageUserData = Promise.all(messages.map(async (message) => {
        const user = await Users.findById(message.senderId);
        return {
          user: {
            id: user._id,
            email: user.email,
            fullName: user.fullName
          },
          message: message.message
        };
      }));

      res.status(200).json(await messageUserData);
    };

    const { conversationId } = req.params;

    if (conversationId === 'new') {
      const existingConversation = await Conversations.find({
        members: { $all: [req.query.senderId, req.query.receiverId] }
      });

      if (existingConversation.length > 0) {
        return checkMessages(existingConversation[0]._id);
      } else {
        return res.status(200).json([]);
      }
    }

    checkMessages(conversationId);

  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).send('Internal server error');
  }
});

// Get all users (except self)
app.get('/api/users/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const users = await Users.find({ _id: { $ne: userId } });

    const usersData = Promise.all(users.map(async (user) => {
      return {
        user: {
          email: user.email,
          fullName: user.fullName,
          receiverId: user._id
        }
      };
    }));

    res.status(200).json(await usersData);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).send('Internal server error');
  }
});

// Health Check
app.get('/api/health', (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const status = dbStatus === 1 ? 'success' : 'fail';
    const message = dbStatus === 1 ? 'Database is connected.' : 'Database is not connected.';

    res.status(dbStatus === 1 ? 200 : 500).json({ status, message });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ status: 'error', message: 'Internal Server Error', error: error.message });
  }
});

// Start server
const port = process.env.PORT || 10000;
server.listen(port, () => {
  console.log('Server is running on port', port);
});
