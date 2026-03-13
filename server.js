// ================================================
// PROJECT TRACKER - COMPLETE BACKEND SERVER
// Tech: Node.js + Express + MongoDB + JWT
// ================================================

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const cron = require('node-cron');

dotenv.config();
const app = express();

const isProduction = process.env.NODE_ENV === 'production';

// Fail fast in production when secrets are missing
if (isProduction) {
  const required = ['MONGODB_URI', 'JWT_SECRET', 'FRONTEND_URL'];
  const missing = required.filter((k) => !process.env[k] || String(process.env[k]).trim() === '');
  if (missing.length) {
    throw new Error(`Missing required env vars in production: ${missing.join(', ')}`);
  }
}

// MIDDLEWARE
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());

// MONGODB CONNECTION
const mongoOptions = {
  serverSelectionTimeoutMS: 15000,
};
// Never allow invalid certs in production
if (!isProduction) {
  mongoOptions.tls = true;
  mongoOptions.tlsAllowInvalidCertificates = true;
}

mongoose.connect(process.env.MONGODB_URI, mongoOptions).then(() => console.log('✓ MongoDB connected'))
  .catch(err => console.log('✗ MongoDB error:', err.message));

mongoose.connection.on('error', err => {
  console.log('✗ MongoDB connection error:', err.message);
});
mongoose.connection.on('disconnected', () => {
  console.log('✗ MongoDB disconnected');
});

// ================================================
// DATABASE SCHEMAS
// ================================================

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, enum: ['freelancer', 'client'], required: true },
  settings: {
    notificationEmail: String,
    notificationDay: { type: Number, default: 1 }
  },
  createdAt: { type: Date, default: Date.now }
});

const ProjectSchema = new mongoose.Schema({
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  freelancerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  description: String,
  hourlyRate: { type: Number, required: true },
  allocatedHours: Number,
  allocatedBudget: Number,
  status: { type: String, enum: ['active', 'completed', 'paused'], default: 'active' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const TimeEntrySchema = new mongoose.Schema({
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  freelancerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  date: { type: Date, required: true },
  hoursWorked: { type: Number, required: true },
  description: String,
  createdAt: { type: Date, default: Date.now }
});

const WeeklySummarySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  role: { type: String, enum: ['freelancer', 'client'], required: true },
  weekStartDate: { type: Date, required: true },
  weekEndDate: Date,
  projects: [{
    projectId: mongoose.Schema.Types.ObjectId,
    projectName: String,
    projectDescription: String,
    hoursLogged: Number,
    hourlyRate: Number,
    totalEarnings: Number,
    totalSpent: Number
  }],
  totalHours: Number,
  totalEarnings: Number,
  totalSpent: Number,
  emailSentAt: Date,
  viewedAt: Date
});

const ViewNotificationSchema = new mongoose.Schema({
  freelancerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  viewedAt: { type: Date, required: true },
  notificationSentAt: { type: Date, default: Date.now }
});

const NotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// MODELS
const User = mongoose.model('User', UserSchema);
const Project = mongoose.model('Project', ProjectSchema);
const TimeEntry = mongoose.model('TimeEntry', TimeEntrySchema);
const WeeklySummary = mongoose.model('WeeklySummary', WeeklySummarySchema);
const ViewNotification = mongoose.model('ViewNotification', ViewNotificationSchema);
const Notification = mongoose.model('Notification', NotificationSchema);

// ================================================
// MIDDLEWARE & UTILITIES
// ================================================

// JWT Authentication
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    req.role = decoded.role;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Role Check
const checkRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.role)) return res.status(403).json({ error: 'Forbidden' });
  next();
};

const isValidObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

const getProjectForRequest = async (req, projectId) => {
  if (!isValidObjectId(projectId)) return null;
  const query = { _id: projectId };
  if (req.role === 'freelancer') query.freelancerId = req.userId;
  if (req.role === 'client') query.clientId = req.userId;
  return await Project.findOne(query);
};

const ensureProjectAccess = async (req, res, next) => {
  const projectId = req.params.id || req.body.projectId;
  const project = await getProjectForRequest(req, projectId);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  req.project = project;
  next();
};

// Email Setup
const transporter = nodemailer.createTransport({
  service: process.env.SMTP_SERVICE || 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// ================================================
// AUTH ROUTES
// ================================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, role } = req.body;
    
    if (await User.findOne({ email })) {
      return res.status(400).json({ error: 'User exists' });
    }
    
    const hashedPassword = await bcryptjs.hash(password, 10);
    const user = new User({
      email,
      password: hashedPassword,
      name,
      role,
      settings: {
        notificationEmail: email,
        notificationDay: 1
      }
    });
    
    await user.save();
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.status(201).json({ 
      token, 
      user: { id: user._id, email, name, role } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user || !(await bcryptjs.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );
    
    res.json({ 
      token, 
      user: { id: user._id, email: user.email, name: user.name, role: user.role } 
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/clients', authMiddleware, async (req, res) => {
  try {
    const clients = await User.find({ role: 'client' }).select('name email');
    res.json(clients);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/freelancers', authMiddleware, async (req, res) => {
  try {
    const freelancers = await User.find({ role: 'freelancer' }).select('name email');
    res.json(freelancers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================
// FREELANCER ROUTES
// ================================================

// Dashboard
app.get('/api/freelancer/dashboard', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const projects = await Project.find({ freelancerId: req.userId }).populate('clientId', 'name');
    const timeEntries = await TimeEntry.find({ freelancerId: req.userId });
    
    const stats = projects.map(p => {
      const entries = timeEntries.filter(e => e.projectId.toString() === p._id.toString());
      const hours = entries.reduce((sum, e) => sum + e.hoursWorked, 0);
      const earnings = hours * p.hourlyRate;
      return { ...p.toObject(), hoursLogged: hours, earnings };
    });
    
    res.json({
      projects: stats,
      totalHours: stats.reduce((s, p) => s + p.hoursLogged, 0),
      totalEarnings: stats.reduce((s, p) => s + p.earnings, 0)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Projects
app.get('/api/freelancer/projects', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const projects = await Project.find({ freelancerId: req.userId }).populate('clientId', 'name email');
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Project
app.post('/api/freelancer/projects', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const project = new Project({
      freelancerId: req.userId,
      ...req.body
    });
    await project.save();
    res.status(201).json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Project
app.put('/api/freelancer/projects/:id', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const project = await Project.findOneAndUpdate(
      { _id: req.params.id, freelancerId: req.userId },
      req.body,
      { new: true }
    );
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Project
app.delete('/api/freelancer/projects/:id', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const deleted = await Project.findOneAndDelete({ _id: req.params.id, freelancerId: req.userId });
    if (!deleted) return res.status(404).json({ error: 'Project not found' });
    res.json({ message: 'Project deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Time Entries
app.get('/api/freelancer/time-entries', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const entries = await TimeEntry.find({ freelancerId: req.userId })
      .populate('projectId', 'name')
      .sort({ date: -1 });
    res.json(entries);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Log Hours
app.post('/api/freelancer/time-entries', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    // Ensure the entry is for a project owned by this freelancer
    const project = await Project.findOne({ _id: req.body.projectId, freelancerId: req.userId });
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const entry = new TimeEntry({
      freelancerId: req.userId,
      date: new Date(req.body.date),
      ...req.body
    });
    await entry.save();

    // Notify the client that hours were logged
    const freelancer = await User.findById(req.userId).select('name');
    if (project && freelancer) {
      await Notification.create({
        userId: project.clientId,
        message: `${freelancer.name} logged ${req.body.hoursWorked}h on "${project.name}"${req.body.description ? ': ' + req.body.description : ''}`
      });
    }

    res.status(201).json(entry);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Time Entry
app.put('/api/freelancer/time-entries/:id', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const entry = await TimeEntry.findOneAndUpdate(
      { _id: req.params.id, freelancerId: req.userId },
      req.body,
      { new: true }
    );
    if (!entry) return res.status(404).json({ error: 'Entry not found' });
    res.json(entry);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete Time Entry
app.delete('/api/freelancer/time-entries/:id', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const deleted = await TimeEntry.findOneAndDelete({ _id: req.params.id, freelancerId: req.userId });
    if (!deleted) return res.status(404).json({ error: 'Entry not found' });
    res.json({ message: 'Entry deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================
// CLIENT ROUTES
// ================================================

// Dashboard
app.get('/api/client/dashboard', authMiddleware, checkRole(['client']), async (req, res) => {
  try {
    const projects = await Project.find({ clientId: req.userId }).populate('freelancerId', 'name');
    
    const withData = await Promise.all(projects.map(async (p) => {
      const entries = await TimeEntry.find({ projectId: p._id });
      const hours = entries.reduce((s, e) => s + e.hoursWorked, 0);
      return {
        ...p.toObject(),
        hoursLogged: hours,
        totalSpent: hours * p.hourlyRate
      };
    }));
    
    res.json({
      projects: withData,
      totalSpent: withData.reduce((s, p) => s + p.totalSpent, 0),
      totalAllocated: withData.reduce((s, p) => s + (p.allocatedBudget || 0), 0)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Projects
app.get('/api/client/projects', authMiddleware, checkRole(['client']), async (req, res) => {
  try {
    const projects = await Project.find({ clientId: req.userId }).populate('freelancerId', 'name email');
    res.json(projects);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create Project
app.post('/api/client/projects', authMiddleware, checkRole(['client']), async (req, res) => {
  try {
    const project = new Project({
      clientId: req.userId,
      ...req.body
    });
    await project.save();
    res.status(201).json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Project
app.put('/api/client/projects/:id', authMiddleware, checkRole(['client']), async (req, res) => {
  try {
    const project = await Project.findOneAndUpdate(
      { _id: req.params.id, clientId: req.userId },
      req.body,
      { new: true }
    );
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// View Project (Logs notification)
app.get('/api/client/projects/:id', authMiddleware, checkRole(['client']), async (req, res) => {
  try {
    const project = await Project.findOne({ _id: req.params.id, clientId: req.userId }).populate('freelancerId');
    if (!project) return res.status(404).json({ error: 'Project not found' });
    const entries = await TimeEntry.find({ projectId: req.params.id });
    const hours = entries.reduce((s, e) => s + e.hoursWorked, 0);
    
    // Log view notification
    await ViewNotification.create({
      freelancerId: project.freelancerId._id,
      clientId: req.userId,
      projectId: req.params.id,
      viewedAt: new Date()
    });

    // Create notification for the freelancer
    const client = await User.findById(req.userId).select('name');
    await Notification.create({
      userId: project.freelancerId._id,
      message: `${client?.name || 'A client'} reviewed your work log for "${project.name}"`
    });
    
    res.json({
      project,
      entries,
      hoursLogged: hours,
      totalSpent: hours * project.hourlyRate
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================
// SUMMARIES & NOTIFICATIONS
// ================================================

// Generate Summaries
const generateSummaries = async () => {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - 7);
  
  // Freelancer summaries
  const freelancers = await User.find({ role: 'freelancer' });
  for (const freelancer of freelancers) {
    const entries = await TimeEntry.find({
      freelancerId: freelancer._id,
      createdAt: { $gte: startDate }
    }).populate('projectId');
    
    const projectMap = {};
    entries.forEach(e => {
      if (!projectMap[e.projectId._id]) {
        projectMap[e.projectId._id] = {
          projectId: e.projectId._id,
          projectName: e.projectId.name,
          projectDescription: e.projectId.description,
          hoursLogged: 0,
          hourlyRate: e.projectId.hourlyRate,
          totalEarnings: 0
        };
      }
      projectMap[e.projectId._id].hoursLogged += e.hoursWorked;
      projectMap[e.projectId._id].totalEarnings += e.hoursWorked * e.projectId.hourlyRate;
    });
    
    const projects = Object.values(projectMap);
    const summary = new WeeklySummary({
      userId: freelancer._id,
      role: 'freelancer',
      weekStartDate: startDate,
      weekEndDate: new Date(),
      projects,
      totalHours: projects.reduce((s, p) => s + p.hoursLogged, 0),
      totalEarnings: projects.reduce((s, p) => s + p.totalEarnings, 0),
      emailSentAt: new Date()
    });
    await summary.save();

    // In-app weekly notification for freelancer
    if (projects.length > 0) {
      const weekLabel = `${startDate.toLocaleDateString()} – ${new Date().toLocaleDateString()}`;
      const projectLines = projects.map(p => `${p.projectName}: ${p.hoursLogged}h ($${p.totalEarnings.toFixed(2)})`).join(', ');
      await Notification.create({
        userId: freelancer._id,
        message: `📋 Weekly Summary (${weekLabel}): ${projectLines} — Total: ${summary.totalHours}h / $${summary.totalEarnings.toFixed(2)}`
      });
    }

    // Send email
    if (process.env.SMTP_USER) {
      try {
        await transporter.sendMail({
          to: freelancer.settings.notificationEmail || freelancer.email,
          subject: `Weekly Summary - ${startDate.toLocaleDateString()}`,
          html: `
            <h2>Your Weekly Summary</h2>
            <p><strong>Total Hours:</strong> ${summary.totalHours}</p>
            <p><strong>Total Earnings:</strong> $${summary.totalEarnings.toFixed(2)}</p>
            <h3>Projects</h3>
            <ul>
              ${projects.map(p => `<li><strong>${p.projectName}:</strong> ${p.hoursLogged}h @ $${p.hourlyRate}/h = $${p.totalEarnings.toFixed(2)}</li>`).join('')}
            </ul>
          `
        });
      } catch (emailErr) {
        console.log('Freelancer email failed:', emailErr.message);
      }
    }
  }
  
  // Client summaries
  const clients = await User.find({ role: 'client' });
  for (const client of clients) {
    const projects = await Project.find({ clientId: client._id });
    
    const projectList = [];
    for (const p of projects) {
      const entries = await TimeEntry.find({
        projectId: p._id,
        createdAt: { $gte: startDate }
      });
      const hours = entries.reduce((s, e) => s + e.hoursWorked, 0);
      projectList.push({
        projectId: p._id,
        projectName: p.name,
        projectDescription: p.description,
        hoursLogged: hours,
        hourlyRate: p.hourlyRate,
        totalSpent: hours * p.hourlyRate
      });
    }
    
    const summary = new WeeklySummary({
      userId: client._id,
      role: 'client',
      weekStartDate: startDate,
      weekEndDate: new Date(),
      projects: projectList,
      totalHours: projectList.reduce((s, p) => s + p.hoursLogged, 0),
      totalSpent: projectList.reduce((s, p) => s + p.totalSpent, 0),
      emailSentAt: new Date()
    });
    await summary.save();

    // In-app weekly notification for client
    const weekLabel = `${startDate.toLocaleDateString()} – ${new Date().toLocaleDateString()}`;
    const projectLines = projectList.filter(p => p.hoursLogged > 0)
      .map(p => `${p.projectName}: ${p.hoursLogged}h ($${p.totalSpent.toFixed(2)})`).join(', ');
    if (projectList.some(p => p.hoursLogged > 0)) {
      await Notification.create({
        userId: client._id,
        message: `📋 Weekly Summary (${weekLabel}): ${projectLines || 'No hours logged'} — Total: ${projectList.reduce((s,p)=>s+p.hoursLogged,0)}h / $${projectList.reduce((s,p)=>s+p.totalSpent,0).toFixed(2)}`
      });
    }

    if (process.env.SMTP_USER) {
      await transporter.sendMail({
        to: client.settings.notificationEmail || client.email,
        subject: `Spending Summary - ${startDate.toLocaleDateString()}`,
        html: `
          <h2>Your Spending Summary</h2>
          <p><strong>Total Hours Logged:</strong> ${summary.totalHours}</p>
          <p><strong>Total Spent:</strong> $${summary.totalSpent.toFixed(2)}</p>
          <h3>Projects</h3>
          <ul>
            ${projectList.map(p => `<li><strong>${p.projectName}:</strong> ${p.hoursLogged}h @ $${p.hourlyRate}/h = $${p.totalSpent.toFixed(2)}</li>`).join('')}
          </ul>
        `
      });
    }
  }
};

// Schedule for Monday 9 AM
cron.schedule('0 9 * * 1', generateSummaries);

// Manual trigger
app.post('/api/summaries/generate', authMiddleware, async (req, res) => {
  try {
    await generateSummaries();
    res.json({ message: 'Summaries generated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Weekly Summary
app.get('/api/summaries/weekly', authMiddleware, async (req, res) => {
  try {
    const summary = await WeeklySummary.findOne({ userId: req.userId }).sort({ weekStartDate: -1 });
    res.json(summary || null);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Summary History
app.get('/api/summaries/history', authMiddleware, async (req, res) => {
  try {
    const summaries = await WeeklySummary.find({ userId: req.userId }).sort({ weekStartDate: -1 });
    res.json(summaries);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark as Viewed
app.put('/api/summaries/:id/viewed', authMiddleware, async (req, res) => {
  try {
    const summary = await WeeklySummary.findByIdAndUpdate(req.params.id, { viewedAt: new Date() }, { new: true });
    res.json(summary);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Notifications
app.get('/api/view-notifications', authMiddleware, checkRole(['freelancer']), async (req, res) => {
  try {
    const notifications = await ViewNotification.find({ freelancerId: req.userId })
      .populate('clientId', 'name email')
      .populate('projectId', 'name')
      .sort({ notificationSentAt: -1 });
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================
// NOTIFICATION ROUTES
// ================================================

app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const notifications = await Notification.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(50);
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/notifications/read-all', authMiddleware, async (req, res) => {
  try {
    await Notification.updateMany({ userId: req.userId, read: false }, { read: true });
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/notifications/:id/read', authMiddleware, async (req, res) => {
  try {
    const notification = await Notification.findByIdAndUpdate(
      req.params.id, { read: true }, { new: true }
    );
    res.json(notification);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ================================================
// START SERVER
// ================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✓ Server running on port ${PORT}`));

module.exports = app;
