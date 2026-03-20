require('dotenv').config();

// Catch unhandled errors so Railway logs show the real cause
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err.message);
  console.error(err.stack);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Rejection:', reason);
});

console.log('🚀 SafeNet starting...');
console.log('   Node version:', process.version);
console.log('   DB_PATH:', process.env.DB_PATH || './safenet.db');
console.log('   PORT:', process.env.PORT || 3000);
console.log('   AI enabled:', !!process.env.ANTHROPIC_API_KEY);
const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const axios     = require('axios');
const Database  = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path      = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
console.log(`🔌 Binding to port ${PORT} on 0.0.0.0`);
const JWT_SECRET     = process.env.JWT_SECRET     || 'safenet_secret_2026';
const ANTHROPIC_KEY  = process.env.ANTHROPIC_API_KEY || '';

// ── MIDDLEWARE ──────────────────────────────────
app.set('trust proxy', 1);
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Explicit page routes
app.get('/',              (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/login',         (req,res) => res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/register',      (req,res) => res.sendFile(path.join(__dirname,'public','register.html')));
app.get('/dashboard',     (req,res) => res.sendFile(path.join(__dirname,'public','dashboard.html')));
app.get('/admin',         (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/login.html',    (req,res) => res.sendFile(path.join(__dirname,'public','login.html')));
app.get('/register.html', (req,res) => res.sendFile(path.join(__dirname,'public','register.html')));
app.get('/dashboard.html',(req,res) => res.sendFile(path.join(__dirname,'public','dashboard.html')));
app.get('/admin.html',    (req,res) => res.sendFile(path.join(__dirname,'public','admin.html')));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));

// ── DATABASE ────────────────────────────────────
const fs = require('fs');
const DB_PATH = process.env.DB_PATH || './safenet.db';

// Auto-create directory if it doesn't exist (e.g. /data on Railway)
try {
  const dbDir = path.dirname(DB_PATH);
  if (dbDir && dbDir !== '.' && !fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log(`✅ Created database directory: ${dbDir}`);
  }
} catch(e) {
  console.warn(`⚠️ Could not create DB directory, using ./safenet.db instead: ${e.message}`);
}

let db;
try {
  db = new Database(DB_PATH);
  console.log(`✅ Database opened: ${DB_PATH}`);
} catch(e) {
  console.error(`❌ Failed to open database at ${DB_PATH}: ${e.message}`);
  console.log('⚠️ Falling back to in-memory database');
  try {
    db = new Database(':memory:');
    console.log('✅ In-memory database opened');
  } catch(e2) {
    console.error('❌ Fatal: cannot open any database:', e2.message);
    process.exit(1);
  }
}
try {
  db.pragma('journal_mode = WAL');
} catch(e) { console.warn('WAL mode not available:', e.message); }

try {
  db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    role        TEXT DEFAULT 'user',
    status      TEXT DEFAULT 'active',
    avatar      TEXT,
    bio         TEXT,
    createdAt   TEXT NOT NULL,
    lastLogin   TEXT
  );
  CREATE TABLE IF NOT EXISTS detections (
    id              TEXT PRIMARY KEY,
    userId          TEXT,
    content         TEXT NOT NULL,
    platform        TEXT,
    verdict         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      INTEGER DEFAULT 0,
    categories      TEXT NOT NULL,
    flags           TEXT,
    explanation     TEXT,
    mitigation      TEXT,
    counterNarrative TEXT,
    shouldReport    INTEGER DEFAULT 0,
    reportPlatform  TEXT,
    createdAt       TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS reports (
    id            TEXT PRIMARY KEY,
    userId        TEXT,
    detectionId   TEXT,
    incidentType  TEXT NOT NULL,
    platform      TEXT NOT NULL,
    targetVictim  TEXT,
    description   TEXT NOT NULL,
    evidence      TEXT,
    status        TEXT DEFAULT 'open',
    priority      TEXT DEFAULT 'medium',
    aiGuidance    TEXT,
    refNumber     TEXT UNIQUE,
    anonymous     INTEGER DEFAULT 0,
    createdAt     TEXT NOT NULL,
    updatedAt     TEXT NOT NULL,
    resolvedAt    TEXT,
    notes         TEXT
  );
  CREATE TABLE IF NOT EXISTS mitigations (
    id          TEXT PRIMARY KEY,
    userId      TEXT,
    detectionId TEXT,
    action      TEXT NOT NULL,
    platform    TEXT,
    details     TEXT,
    outcome     TEXT DEFAULT 'pending',
    createdAt   TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS resources (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT,
    category    TEXT,
    url         TEXT,
    icon        TEXT,
    featured    INTEGER DEFAULT 0,
    createdAt   TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id        TEXT PRIMARY KEY,
    userId    TEXT NOT NULL,
    message   TEXT NOT NULL,
    type      TEXT DEFAULT 'info',
    read      INTEGER DEFAULT 0,
    createdAt TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS chat_sessions (
    id        TEXT PRIMARY KEY,
    userId    TEXT,
    messages  TEXT NOT NULL,
    createdAt TEXT NOT NULL,
    updatedAt TEXT NOT NULL
  );
`);
  console.log('✅ Database schema ready');
} catch(e) {
  console.error('❌ Schema creation failed:', e.message);
  process.exit(1);
}

// Safe column additions
const addCol = (t,c,tp) => { try { db.prepare(`ALTER TABLE ${t} ADD COLUMN ${c} ${tp}`).run(); } catch {} };
addCol('detections','platform','TEXT');
addCol('reports','targetVictim','TEXT');

const now = () => new Date().toISOString();
const genRef = () => 'SN-' + Math.random().toString(36).substring(2,8).toUpperCase();

// ── SEED ────────────────────────────────────────
function seedData() {
  if (!db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get()) {
    db.prepare(`INSERT INTO users (id,name,email,password,role,status,createdAt,lastLogin) VALUES (?,?,?,?,?,?,?,?)`)
      .run(uuidv4(),'Admin','admin@safenet.com',bcrypt.hashSync('Admin@2024',10),'admin','active',now(),now());
    console.log('✅ Admin: admin@safenet.com / Admin@2024');
  }
  if (!db.prepare('SELECT COUNT(*) as c FROM resources').get().c) {
    const res = [
      {title:'Crisis Text Line',desc:'Text HOME to 741741 — free 24/7 crisis counseling',cat:'crisis',icon:'🆘',f:1},
      {title:'Cyberbullying Research Center',desc:'Research, facts, and resources about cyberbullying',cat:'education',icon:'📚',f:1},
      {title:'StopBullying.gov',desc:'Official US government resource for bullying prevention',cat:'prevention',icon:'🛡️',f:0},
      {title:'Cyber Civil Rights Initiative',desc:'Support for victims of image-based abuse and harassment',cat:'support',icon:'⚖️',f:1},
      {title:'National Suicide Prevention Lifeline',desc:'Call 988 — free 24/7 mental health crisis support',cat:'crisis',icon:'💙',f:1},
      {title:'Internet Watch Foundation',desc:'Report illegal online content and get legal guidance',cat:'reporting',icon:'🔍',f:0},
      {title:'Anti-Defamation League',desc:'Combat hate speech and online discrimination',cat:'support',icon:'✊',f:0},
      {title:'Digital Wellness Collective',desc:'Tools and guides for healthy online behavior',cat:'wellness',icon:'🌱',f:0},
      {title:'ConnectSafely',desc:'Safety tips, privacy guides, and parental resources',cat:'education',icon:'🔒',f:0},
      {title:'PACER National Bullying Prevention',desc:'Resources for students, parents and educators',cat:'prevention',icon:'🎓',f:0},
    ];
    const ins = db.prepare('INSERT INTO resources (id,title,description,category,icon,featured,createdAt) VALUES (?,?,?,?,?,?,?)');
    res.forEach(r => ins.run(uuidv4(),r.title,r.desc,r.cat,r.icon,r.f,now()));
  }
}
seedData();

// ── HELPERS ─────────────────────────────────────
function addNotif(userId,message,type='info') {
  try { db.prepare('INSERT INTO notifications (id,userId,message,type,read,createdAt) VALUES (?,?,?,?,0,?)').run(uuidv4(),userId,message,type,now()); } catch {}
}

// ── AUTH ─────────────────────────────────────────
function authUser(req,res,next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({error:'Unauthorized'});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({error:'Token invalid or expired'}); }
}
function authAdmin(req,res,next) {
  authUser(req,res,() => {
    if (req.user.role !== 'admin') return res.status(403).json({error:'Admin only'});
    next();
  });
}
function optAuth(req,res,next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) { try { req.user = jwt.verify(token,JWT_SECRET); } catch {} }
  next();
}

// ── AI ENGINE ────────────────────────────────────
async function analyzeWithAI(content, platform='unknown') {
  const prompt = `You are SafeNet AI, an expert cyberbullying detection and mitigation system.

Analyze the following online content for cyberbullying, harassment and harmful behavior.

Platform: ${platform}
Content: "${content.substring(0,2000)}"

Respond ONLY in this exact JSON format, no markdown, no text outside JSON:
{
  "verdict": "safe|low_risk|moderate|severe|critical",
  "severity": "none|low|medium|high|extreme",
  "confidence": 0-100,
  "explanation": "2-3 clear sentences explaining what was found and why it is or isn't harmful",
  "categories": {
    "direct_harassment": 0-100,
    "hate_speech": 0-100,
    "threats_violence": 0-100,
    "sexual_harassment": 0-100,
    "identity_attack": 0-100,
    "public_shaming": 0-100,
    "doxxing": 0-100,
    "manipulation": 0-100
  },
  "flags": ["specific behavior 1", "specific behavior 2"],
  "victim_impact": "brief description of potential psychological impact on target",
  "mitigation": {
    "immediate": ["action 1", "action 2"],
    "platform_report": "exact steps to report on ${platform}",
    "legal_options": "brief description of legal avenues if applicable"
  },
  "counter_narrative": "a constructive counter-message or reframe that could defuse the situation, or null if not applicable",
  "should_report": true|false,
  "report_to": "platform name or authority"
}`;

  // No API key — use demo mode
  if (!ANTHROPIC_KEY) {
    console.log('⚠️  No ANTHROPIC_API_KEY set — using demo analysis');
    return getDemoAnalysis(content);
  }

  try {
    const r = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1200,
      messages: [{ role:'user', content:prompt }]
    }, {
      headers: {
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Type': 'application/json'
      }
    });
    const raw = r.data.content?.[0]?.text || '{}';
    return JSON.parse(raw.replace(/```json|```/g,'').trim());
  } catch(e) {
    const status  = e.response?.status;
    const errBody = e.response?.data;
    console.error(`❌ Anthropic API error ${status}:`, JSON.stringify(errBody));

    if (status === 401) {
      console.error('→ Invalid API key. Check ANTHROPIC_API_KEY in Railway Variables.');
    } else if (status === 400) {
      console.error('→ Bad request to Anthropic. Model or payload issue.');
    } else if (status === 429) {
      console.error('→ Rate limit hit. Too many requests.');
    }

    // Always fall back to demo rather than crashing
    console.log('⚠️  Falling back to demo analysis');
    return getDemoAnalysis(content);
  }
}

function getDemoAnalysis(content) {
  const hasThreat  = /kill|hurt|attack|find you|know where|stab|dead|destroy/i.test(content);
  const hasBully   = /worthless|ugly|stupid|loser|pathetic|nobody likes|kill yourself|kys|freak|disgusting/i.test(content);
  const hasHate    = /slur|inferior|go back|hate.*people|they are all|subhuman/i.test(content);
  const hasDox     = /address|home|school|phone number|i know where you live/i.test(content);
  const hasSexual  = /sexy|send pic|nudes|sexual|body|inappropriate/i.test(content);
  const hasShame   = /everyone knows|screenshot|share|expose|embarrass/i.test(content);

  if (hasThreat) return {verdict:'critical',severity:'extreme',confidence:95,explanation:'This content contains direct threats of physical harm and targeted intimidation. This constitutes criminal threatening behavior that warrants immediate law enforcement involvement.',categories:{direct_harassment:90,hate_speech:40,threats_violence:95,sexual_harassment:5,identity_attack:30,public_shaming:20,doxxing:10,manipulation:60},flags:['Physical threats detected','Targeted intimidation','Potential criminal conduct'],victim_impact:'Severe psychological trauma, fear for physical safety, anxiety and hypervigilance',mitigation:{immediate:['Save all evidence as screenshots','Block the sender immediately','Contact law enforcement if you feel unsafe'],platform_report:'Go to the post → tap ⋮ → Report → Harassment/Threats',legal_options:'Threatening messages can constitute criminal harassment or assault under most jurisdictions. File a police report.'},counter_narrative:null,should_report:true,report_to:'Platform and law enforcement'};
  if (hasDox) return {verdict:'critical',severity:'extreme',confidence:92,explanation:'Doxxing detected — personal identifying information is being weaponized to intimidate. This is a serious privacy violation and can enable physical harm.',categories:{direct_harassment:80,hate_speech:20,threats_violence:70,sexual_harassment:5,identity_attack:40,public_shaming:60,doxxing:95,manipulation:70},flags:['Personal information exposure','Doxxing behavior','Privacy violation'],victim_impact:'Extreme fear and vulnerability, risk of physical harm, loss of sense of safety',mitigation:{immediate:['Document all evidence','Lock down all social media profiles to private','Alert trusted adults or authorities'],platform_report:'Report as "Sharing Private Information" on the platform',legal_options:'Doxxing may violate computer fraud, stalking, and privacy laws. Consult a lawyer or contact police.'},counter_narrative:null,should_report:true,report_to:'Platform trust & safety and law enforcement'};
  if (hasBully) return {verdict:'severe',severity:'high',confidence:88,explanation:'Clear cyberbullying patterns detected including degrading language, personal attacks and encouragement of self-harm. This is targeted psychological abuse.',categories:{direct_harassment:90,hate_speech:25,threats_violence:15,sexual_harassment:5,identity_attack:50,public_shaming:40,doxxing:5,manipulation:55},flags:['Personal degradation','Encouraging self-harm','Repeated targeting'],victim_impact:'Severe damage to self-esteem, depression, anxiety, risk of self-harm behavior',mitigation:{immediate:['Do not respond to the bully','Block and restrict the account','Talk to a trusted person about what happened'],platform_report:'Report as "Bullying or Harassment" — provide screenshots as evidence',legal_options:'Repeated cyberbullying may constitute criminal harassment in many jurisdictions.'},counter_narrative:'Your worth is not determined by what others say. This behavior reflects on the bully, not on you.',should_report:true,report_to:'Platform safety team and school counselor if minors involved'};
  if (hasHate) return {verdict:'severe',severity:'high',confidence:85,explanation:'Hate speech detected targeting individuals based on identity characteristics. This content promotes discrimination and dehumanization.',categories:{direct_harassment:60,hate_speech:90,threats_violence:20,sexual_harassment:5,identity_attack:95,public_shaming:30,doxxing:5,manipulation:40},flags:['Identity-based attack','Dehumanizing language','Discriminatory content'],victim_impact:'Deep psychological harm, sense of being unsafe, community-level trauma',mitigation:{immediate:['Document the hate speech','Report to platform immediately','Reach out to community support organizations'],platform_report:'Report as "Hate Speech" targeting protected characteristics',legal_options:'Hate speech laws vary by country. In many places this can be reported to authorities.'},counter_narrative:'Diversity makes communities stronger. Dehumanizing language has no place in civil discourse.',should_report:true,report_to:'Platform trust & safety team'};
  if (hasSexual) return {verdict:'moderate',severity:'medium',confidence:78,explanation:'Potentially inappropriate sexual content or sexual harassment detected. This can constitute a form of online sexual abuse.',categories:{direct_harassment:55,hate_speech:10,threats_violence:5,sexual_harassment:80,identity_attack:20,public_shaming:30,doxxing:5,manipulation:60},flags:['Sexual harassment patterns','Inappropriate requests','Unwanted sexual attention'],victim_impact:'Discomfort, anxiety, sense of violation and objectification',mitigation:{immediate:['Block the person immediately','Do not share any images','Report to a trusted adult if you are a minor'],platform_report:'Report as "Sexual Harassment" or "Inappropriate Content"',legal_options:'Sexual harassment online can be actionable legally, especially involving minors.'},counter_narrative:null,should_report:true,report_to:'Platform safety and parents/guardians if minor'};
  if (hasShame) return {verdict:'moderate',severity:'medium',confidence:75,explanation:'Public shaming behavior detected — content designed to humiliate or expose someone to ridicule. This is a form of coordinated harassment.',categories:{direct_harassment:65,hate_speech:15,threats_violence:5,sexual_harassment:10,identity_attack:30,public_shaming:85,doxxing:20,manipulation:70},flags:['Humiliation tactics','Public exposure attempt','Coordinated shaming'],victim_impact:'Severe embarrassment, social anxiety, school/work avoidance behavior',mitigation:{immediate:['Document evidence before it is deleted','Contact platform to remove content','Request takedown if private images are involved'],platform_report:'Report as "Bullying" or "Sharing Private Information"',legal_options:'Non-consensual image sharing is illegal in many countries.'},counter_narrative:'No one deserves to be publicly humiliated. This behavior can have devastating real-world consequences.',should_report:true,report_to:'Platform safety team'};
  return {verdict:'safe',severity:'none',confidence:94,explanation:'No significant cyberbullying or harmful content detected. The content appears to be within normal social interaction boundaries.',categories:{direct_harassment:4,hate_speech:2,threats_violence:1,sexual_harassment:1,identity_attack:2,public_shaming:3,doxxing:0,manipulation:5},flags:[],victim_impact:'No harmful impact detected',mitigation:{immediate:['No immediate action needed'],platform_report:'No report necessary',legal_options:'No legal action needed'},counter_narrative:null,should_report:false,report_to:null};
}

async function getAIGuidance(type, platform, description) {
  const fallback = `Your report has been received. Immediate steps:\n\n1. Document all evidence with screenshots and timestamps.\n2. Report directly to ${platform} using their built-in reporting tools.\n3. Block the perpetrator to prevent further contact.\n4. Tell a trusted person — you don't have to face this alone.\n5. If you feel physically threatened, contact law enforcement immediately.\n\nA SafeNet moderator will review your case within 24 hours.`;

  if (!ANTHROPIC_KEY) return fallback;

  try {
    const r = await axios.post('https://api.anthropic.com/v1/messages', {
      model: 'claude-sonnet-4-20250514', max_tokens: 600,
      messages: [{ role:'user', content:`You are SafeNet AI support. Victim reporting: ${type} on ${platform}. Description: "${description.substring(0,400)}". Provide empathetic, practical numbered steps (5 max). Include ${platform}-specific reporting instructions. Under 200 words. Plain text.` }]
    }, { headers: { 'x-api-key':ANTHROPIC_KEY, 'anthropic-version':'2023-06-01', 'Content-Type':'application/json' }});
    return r.data.content?.[0]?.text || fallback;
  } catch(e) {
    console.error('❌ Anthropic guidance error:', e.response?.status, e.response?.data?.error?.message);
    return fallback;
  }
}

// ── AUTH ROUTES ──────────────────────────────────
app.post('/api/auth/register', async (req,res) => {
  try {
    const {name,email,password} = req.body;
    if (!name||!email||!password) return res.status(400).json({error:'All fields required'});
    if (password.length < 8) return res.status(400).json({error:'Password must be 8+ characters'});
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(400).json({error:'Email already registered'});
    const id = uuidv4();
    db.prepare('INSERT INTO users (id,name,email,password,role,status,createdAt,lastLogin) VALUES (?,?,?,?,?,?,?,?)')
      .run(id,name,email,bcrypt.hashSync(password,10),'user','active',now(),now());
    const token = jwt.sign({id,role:'user'},JWT_SECRET,{expiresIn:'7d'});
    const user = db.prepare('SELECT id,name,email,role,createdAt FROM users WHERE id=?').get(id);
    addNotif(id,'👋 Welcome to SafeNet! Start by analyzing content or filing a report.','success');
    res.json({token,user});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/auth/login', (req,res) => {
  try {
    const {email,password} = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!user) return res.status(400).json({error:'No account found with that email'});
    if (!bcrypt.compareSync(password,user.password)) return res.status(400).json({error:'Incorrect password'});
    if (user.status==='suspended') return res.status(403).json({error:'Account suspended'});
    db.prepare('UPDATE users SET lastLogin=? WHERE id=?').run(now(),user.id);
    const token = jwt.sign({id:user.id,role:user.role},JWT_SECRET,{expiresIn:'7d'});
    const {password:_,...safe} = user;
    res.json({token,user:safe});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/auth/me', authUser, (req,res) => {
  try {
    const user = db.prepare('SELECT id,name,email,role,status,avatar,bio,createdAt,lastLogin FROM users WHERE id=?').get(req.user.id);
    if (!user) return res.status(401).json({error:'User not found'});
    res.json(user);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── DETECTION ROUTES ─────────────────────────────
app.post('/api/detect', optAuth, async (req,res) => {
  try {
    console.log('🔍 /api/detect hit — body:', JSON.stringify(req.body), '| content-type:', req.headers['content-type']);
    const {content, platform} = req.body;
    if (!content || content.trim().length < 3) {
      return res.status(400).json({
        error: `Content too short to analyze. Received: "${content}" (type: ${typeof content}). Body was: ${JSON.stringify(req.body)}`
      });
    }
    const result = await analyzeWithAI(content, platform||'unknown');
    const id = uuidv4();
    db.prepare(`INSERT INTO detections (id,userId,content,platform,verdict,severity,confidence,categories,flags,explanation,mitigation,counterNarrative,shouldReport,reportPlatform,createdAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id,req.user?.id||null,content.substring(0,1000),platform||'unknown',result.verdict,result.severity,result.confidence||0,JSON.stringify(result.categories||{}),JSON.stringify(result.flags||[]),result.explanation,JSON.stringify(result.mitigation||{}),result.counter_narrative||null,result.should_report?1:0,result.report_to||null,now());
    if (req.user?.id && (result.verdict==='critical'||result.verdict==='severe')) {
      addNotif(req.user.id,'⚠️ High-risk content detected in your recent analysis. Please review the mitigation steps.','danger');
    }
    res.json({id,...result});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/detections', authUser, (req,res) => {
  try {
    const rows = db.prepare('SELECT * FROM detections WHERE userId=? ORDER BY createdAt DESC LIMIT 50').all(req.user.id);
    res.json(rows.map(r=>({...r,categories:JSON.parse(r.categories||'{}'),flags:JSON.parse(r.flags||'[]'),mitigation:JSON.parse(r.mitigation||'{}')})));
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── REPORT ROUTES ────────────────────────────────
app.post('/api/reports', optAuth, async (req,res) => {
  try {
    const {incidentType,platform,description,evidence,anonymous,targetVictim,detectionId} = req.body;
    if (!incidentType||!platform||!description) return res.status(400).json({error:'Required fields missing'});
    const id = uuidv4(), ref = genRef();
    const guidance = await getAIGuidance(incidentType,platform,description);
    const userId = anonymous?null:(req.user?.id||null);
    db.prepare(`INSERT INTO reports (id,userId,detectionId,incidentType,platform,targetVictim,description,evidence,status,priority,aiGuidance,refNumber,anonymous,createdAt,updatedAt) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id,userId,detectionId||null,incidentType,platform,targetVictim||null,description,evidence||null,'open','medium',guidance,ref,anonymous?1:0,now(),now());
    if (userId&&!anonymous) addNotif(userId,`📋 Report ${ref} filed. Our team reviews within 24 hours.`,'success');
    res.json({id,refNumber:ref,guidance,status:'open'});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/reports', authUser, (req,res) => {
  try {
    res.json(db.prepare('SELECT * FROM reports WHERE userId=? ORDER BY createdAt DESC LIMIT 50').all(req.user.id));
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/reports/track/:ref', (req,res) => {
  try {
    const r = db.prepare('SELECT id,refNumber,incidentType,platform,status,priority,createdAt,updatedAt FROM reports WHERE refNumber=?').get(req.params.ref.toUpperCase());
    if (!r) return res.status(404).json({error:'Report not found'});
    res.json(r);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── SUPPORT CHAT ─────────────────────────────────
app.post('/api/chat', optAuth, async (req,res) => {
  try {
    const {message,history=[]} = req.body;
    if (!message) return res.status(400).json({error:'Message required'});
    if (!ANTHROPIC_KEY) return res.json({reply:"I'm here to help you navigate cyberbullying safely. Document everything, block the bully, report to the platform, and remember — this is never your fault. For immediate crisis support, text HOME to 741741."});
    const messages = [...history.slice(-6).map(m=>({role:m.role,content:m.content})),{role:'user',content:message}];
    const r = await axios.post('https://api.anthropic.com/v1/messages',{
      model:'claude-sonnet-4-20250514',max_tokens:500,
      system:'You are SafeNet AI, a compassionate support counselor specializing in cyberbullying, online harassment and digital safety. Be empathetic, practical and empowering. Validate feelings. Give specific actionable advice. Reference relevant resources when helpful. Keep responses under 150 words. Never minimize harm.',
      messages
    },{headers:{'x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01','Content-Type':'application/json'}});
    res.json({reply:r.data.content?.[0]?.text||"I'm here to support you."});
  } catch(e) { res.status(500).json({reply:"I'm here to help. Text HOME to 741741 for immediate crisis support."}); }
});

// ── RESOURCES ────────────────────────────────────
app.get('/api/resources', (req,res) => {
  try {
    const {category} = req.query;
    const rows = category
      ? db.prepare('SELECT * FROM resources WHERE category=? ORDER BY featured DESC,title ASC').all(category)
      : db.prepare('SELECT * FROM resources ORDER BY featured DESC,title ASC').all();
    res.json(rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── USER DASHBOARD ───────────────────────────────
app.get('/api/user/dashboard', authUser, (req,res) => {
  try {
    const uid = req.user.id;
    const detections = db.prepare('SELECT * FROM detections WHERE userId=? ORDER BY createdAt DESC LIMIT 10').all(uid);
    const reports    = db.prepare('SELECT * FROM reports WHERE userId=? ORDER BY createdAt DESC LIMIT 10').all(uid);
    const notifs     = db.prepare('SELECT * FROM notifications WHERE userId=? ORDER BY createdAt DESC LIMIT 20').all(uid);
    const stats = {
      totalDetections: db.prepare('SELECT COUNT(*) as c FROM detections WHERE userId=?').get(uid).c,
      harmfulDetected: db.prepare("SELECT COUNT(*) as c FROM detections WHERE userId=? AND verdict NOT IN ('safe','low_risk')").get(uid).c,
      reportsField:    db.prepare('SELECT COUNT(*) as c FROM reports WHERE userId=?').get(uid).c,
      openReports:     db.prepare("SELECT COUNT(*) as c FROM reports WHERE userId=? AND status='open'").get(uid).c,
      criticalFound:   db.prepare("SELECT COUNT(*) as c FROM detections WHERE userId=? AND verdict='critical'").get(uid).c,
    };
    res.json({
      detections: detections.map(d=>({...d,categories:JSON.parse(d.categories||'{}'),flags:JSON.parse(d.flags||'[]')})),
      reports, notifications:notifs, stats
    });
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/user/profile', authUser, (req,res) => {
  try {
    const {name,bio} = req.body;
    db.prepare('UPDATE users SET name=COALESCE(?,name),bio=COALESCE(?,bio) WHERE id=?').run(name||null,bio||null,req.user.id);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/user/password', authUser, (req,res) => {
  try {
    const {currentPassword,newPassword} = req.body;
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (!bcrypt.compareSync(currentPassword,user.password)) return res.status(400).json({error:'Current password incorrect'});
    if ((newPassword||'').length < 8) return res.status(400).json({error:'New password must be 8+ characters'});
    db.prepare('UPDATE users SET password=? WHERE id=?').run(bcrypt.hashSync(newPassword,10),req.user.id);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/user/notifications/read', authUser, (req,res) => {
  try { db.prepare('UPDATE notifications SET read=1 WHERE userId=?').run(req.user.id); res.json({success:true}); }
  catch(e) { res.status(500).json({error:e.message}); }
});

// ── ADMIN ROUTES ─────────────────────────────────
app.get('/api/admin/stats', authAdmin, (req,res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    res.json({
      totalUsers:      db.prepare("SELECT COUNT(*) as c FROM users WHERE role!='admin'").get().c,
      totalDetections: db.prepare('SELECT COUNT(*) as c FROM detections').get().c,
      totalReports:    db.prepare('SELECT COUNT(*) as c FROM reports').get().c,
      openReports:     db.prepare("SELECT COUNT(*) as c FROM reports WHERE status='open'").get().c,
      criticalToday:   db.prepare("SELECT COUNT(*) as c FROM detections WHERE verdict='critical' AND createdAt>=?").get(today).c,
      severeToday:     db.prepare("SELECT COUNT(*) as c FROM detections WHERE verdict IN ('critical','severe') AND createdAt>=?").get(today).c,
      verdictBreakdown: db.prepare('SELECT verdict,COUNT(*) as c FROM detections GROUP BY verdict').all(),
      severityBreakdown:db.prepare('SELECT severity,COUNT(*) as c FROM detections GROUP BY severity').all(),
      recentReports:   db.prepare('SELECT * FROM reports ORDER BY createdAt DESC LIMIT 10').all(),
      recentUsers:     db.prepare("SELECT id,name,email,role,status,createdAt FROM users WHERE role!='admin' ORDER BY createdAt DESC LIMIT 10").all(),
    });
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/admin/reports', authAdmin, (req,res) => {
  try {
    const {status} = req.query;
    const rows = status
      ? db.prepare('SELECT * FROM reports WHERE status=? ORDER BY createdAt DESC').all(status)
      : db.prepare('SELECT * FROM reports ORDER BY createdAt DESC LIMIT 200').all();
    res.json(rows);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/admin/reports/:id', authAdmin, (req,res) => {
  try {
    const {status,priority,notes} = req.body;
    db.prepare('UPDATE reports SET status=COALESCE(?,status),priority=COALESCE(?,priority),notes=COALESCE(?,notes),updatedAt=? WHERE id=?')
      .run(status||null,priority||null,notes||null,now(),req.params.id);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/admin/users', authAdmin, (req,res) => {
  try {
    res.json(db.prepare("SELECT id,name,email,role,status,createdAt,lastLogin FROM users WHERE role!='admin' ORDER BY createdAt DESC").all());
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/admin/users/:id', authAdmin, (req,res) => {
  try {
    db.prepare('UPDATE users SET status=? WHERE id=?').run(req.body.status,req.params.id);
    res.json({success:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/admin/detections', authAdmin, (req,res) => {
  try {
    const rows = db.prepare('SELECT * FROM detections ORDER BY createdAt DESC LIMIT 200').all();
    res.json(rows.map(r=>({...r,categories:JSON.parse(r.categories||'{}'),flags:JSON.parse(r.flags||'[]')})));
  } catch(e) { res.status(500).json({error:e.message}); }
});

// Catch-all
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SafeNet listening on 0.0.0.0:${PORT}`);
  console.log(`   Admin: admin@safenet.com / Admin@2024`);
});

server.on('error', (err) => {
  console.error('❌ Server failed to start:', err.message);
  process.exit(1);
});

module.exports = app;
