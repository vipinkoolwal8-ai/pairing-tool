const express = require("express");
const fs = require("fs");
const path = require("path");
const pino = require("pino");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const chalk = require("chalk");
const {
    makeInMemoryStore,
    useMultiFileAuthState,
    delay,
    makeCacheableSignalKeyStore,
    Browsers,
    fetchLatestBaileysVersion,
    makeWASocket,
    isJidBroadcast
} = require("@whiskeysockets/baileys");

const app = express();
const PORT = 30118;

// Server start time
const SERVER_START_TIME = Date.now();

// Memory management
const MAX_MEMORY_MB = 512;

// Admin credentials
const ADMIN_CREDENTIALS = {
    username: "WALEED KHAN",
    password: "WALEED KHAN786"
};

const CYAN_SEPARATOR = chalk.cyan('═'.repeat(70));

function logInfo(message) {
    console.log(CYAN_SEPARATOR);
    console.log(chalk.cyan('ℹ'), chalk.white(message));
    console.log(CYAN_SEPARATOR);
}
function logSuccess(message) {
    console.log(CYAN_SEPARATOR);
    console.log(chalk.green('✓'), chalk.greenBright(message));
    console.log(CYAN_SEPARATOR);
}
function logError(message) {
    console.log(CYAN_SEPARATOR);
    console.log(chalk.red('✖'), chalk.redBright(message));
    console.log(CYAN_SEPARATOR);
}
function logWarning(message) {
    console.log(CYAN_SEPARATOR);
    console.log(chalk.yellow('⚠'), chalk.yellowBright(message));
    console.log(CYAN_SEPARATOR);
}

// Create directories
["temp", "tasks", "logs", "sessions_backup", "data", "tasks/temp_uploads", "public"].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ===================================================
// FILE PATHS
// ===================================================
const USERS_FILE = path.join("data", "users.json");
const APPROVALS_FILE = path.join("data", "approvals.json");

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([], null, 2));
}
if (!fs.existsSync(APPROVALS_FILE)) {
    fs.writeFileSync(APPROVALS_FILE, JSON.stringify({}, null, 2));
}

const upload = multer({
    dest: "tasks/temp_uploads/",
    limits: { fileSize: 10 * 1024 * 1024 }
});

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());
app.use(express.static('public'));

// ===================================================
// GLOBAL STATE
// ===================================================
const activeClients = new Map();
const activeTasks = new Map();
const taskLogs = new Map();
const userSessions = new Map();
const sessionRestartAttempts = new Map();
const taskRunningLocks = new Map();
const manuallyDisconnectedSessions = new Set();
const pairCodeSessions = new Map();

// 🔥 REMOTE BACKUP LINKS
const remoteBackupLinks = new Map(); // primarySessionId -> backupSessionId

// ===================================================
// HELPERS
// ===================================================
function formatDate(dateInput) {
    const date = new Date(dateInput);
    const day = date.getDate();
    const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    const month = monthNames[date.getMonth()];
    const year = date.getFullYear();
    return `${day} ${month} ${year}`;
}

function formatUptime(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    else if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    else if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    else return `${seconds}s`;
}

// ===================================================
// USERS
// ===================================================
function loadUsers() {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
    catch (error) { logError('Error loading users: ' + error.message); return []; }
}
function saveUsers(users) {
    try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); }
    catch (error) { logError('Error saving users: ' + error.message); }
}
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}
function generateUserId() {
    return 'user_' + Date.now() + '_' + Math.random().toString(36).substring(2, 10);
}
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// ===================================================
// APPROVAL KEY SYSTEM
// ===================================================
function loadApprovals() {
    try { return JSON.parse(fs.readFileSync(APPROVALS_FILE, 'utf8')); }
    catch (error) { logError('Error loading approvals: ' + error.message); return {}; }
}
function saveApprovals(approvals) {
    try { fs.writeFileSync(APPROVALS_FILE, JSON.stringify(approvals, null, 2)); }
    catch (error) { logError('Error saving approvals: ' + error.message); }
}

function generateApprovalKey(fingerprint) {
    try {
        const raw = JSON.stringify({
            ua: fingerprint.userAgent || '',
            lang: fingerprint.language || '',
            plat: fingerprint.platform || '',
            screen: fingerprint.screenResolution || '',
            tz: fingerprint.timezone || '',
            ts: Date.now()
        });
        const hash = crypto.createHash('sha256').update(raw).digest('hex');
        const short = hash.substring(0, 16).toUpperCase();
        const formatted = short.match(/.{1,4}/g).join('-');
        return 'KEY-' + formatted;
    } catch (error) {
        logError('Error generating approval key: ' + error.message);
        return 'KEY-' + Date.now().toString(36).toUpperCase();
    }
}

function isAdminRequest(req) {
    return req.cookies && req.cookies.adminToken === 'admin_authenticated';
}

// ===================================================
// AUTH MIDDLEWARE
// ===================================================
function requireAuth(req, res, next) {
    const token = req.cookies.sessionToken;
    if (!token) return res.redirect('/login');
    const users = loadUsers();
    const user = users.find(u => u.sessionToken === token);
    if (!user) { res.clearCookie('sessionToken'); return res.redirect('/login'); }
    req.user = user;
    next();
}

function requireAdmin(req, res, next) {
    const adminToken = req.cookies.adminToken;
    if (!adminToken || adminToken !== 'admin_authenticated') return res.redirect('/admin-login');
    req.isAdmin = true;
    next();
}

// ===================================================
// PERSISTENT DATA
// ===================================================
function loadPersistentData() {
    try {
        if (fs.existsSync('sessions_backup/activeClients.json')) {
            const data = JSON.parse(fs.readFileSync('sessions_backup/activeClients.json', 'utf8'));
            data.forEach(([key, value]) => {
                activeClients.set(key, {
                    ...value,
                    client: null,
                    isConnected: false,
                    backupActive: value.backupActive || false,
                    isRemoteBackup: value.isRemoteBackup || false
                });
                if (value.remoteBackupSessionId) {
                    remoteBackupLinks.set(key, value.remoteBackupSessionId);
                }
            });
            logSuccess(`Loaded ${activeClients.size} persistent sessions`);
        }
        if (fs.existsSync('sessions_backup/userSessions.json')) {
            const data = JSON.parse(fs.readFileSync('sessions_backup/userSessions.json', 'utf8'));
            data.forEach(([key, value]) => userSessions.set(key, value));
        }
    } catch (error) {
        logError('Error loading persistent data: ' + error.message);
    }
}

function savePersistentData() {
    try {
        const clientsData = Array.from(activeClients.entries())
            .filter(([sessionId]) => !manuallyDisconnectedSessions.has(sessionId))
            .map(([key, value]) => {
                return [key, {
                    number: value.number,
                    authPath: value.authPath,
                    isConnected: value.isConnected,
                    tasks: value.tasks || [],
                    lastActivity: value.lastActivity,
                    userId: value.userId,
                    username: value.username,
                    createdAt: value.createdAt,
                    remoteBackupSessionId: value.remoteBackupSessionId || null,
                    primarySessionId: value.primarySessionId || null,
                    isRemoteBackup: value.isRemoteBackup || false,
                    backupActive: value.backupActive || false,
                    backupActiveFor: value.backupActiveFor || null,
                    pendingActivation: value.pendingActivation || false,
                    pendingFor: value.pendingFor || null
                }];
            });
        fs.writeFileSync('sessions_backup/activeClients.json', JSON.stringify(clientsData));

        const sessionsData = Array.from(userSessions.entries())
            .filter(([sessionId]) => !manuallyDisconnectedSessions.has(sessionId));
        fs.writeFileSync('sessions_backup/userSessions.json', JSON.stringify(sessionsData));
    } catch (error) {
        logError('Error saving persistent data: ' + error.message);
    }
}

loadPersistentData();

function generateSessionId() {
    return 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 17);
}
function generateShortTaskId() {
    return 'task_' + Date.now() + '_' + Math.random().toString(36).substring(2, 8);
}

function optimizeMemory() {
    if (process.memoryUsage().heapUsed > MAX_MEMORY_MB * 1024 * 1024 * 0.8) {
        if (global.gc) global.gc();
        for (let [, logs] of taskLogs.entries()) {
            if (logs.length > 50) logs.splice(50);
        }
    }
}

// ===================================================
// KEYS CLEANUP
// ===================================================
function cleanupSessionKeys() {
    const tempDir = path.join(__dirname, 'temp');
    if (!fs.existsSync(tempDir)) return;
    const KEY_PREFIXES = ['pre-key-','session-','sender-key-','device-list-','tctoken-','lid-mapping-'];
    const sessionFolders = fs.readdirSync(tempDir).filter(f => fs.statSync(path.join(tempDir, f)).isDirectory());
    sessionFolders.forEach(sessionFolder => {
        const sessionPath = path.join(tempDir, sessionFolder);
        try {
            const files = fs.readdirSync(sessionPath);
            const fileGroups = {};
            for (const file of files) {
                if (file === 'creds.json') continue;
                for (const prefix of KEY_PREFIXES) {
                    if (file.startsWith(prefix)) {
                        if (!fileGroups[prefix]) fileGroups[prefix] = [];
                        fileGroups[prefix].push(file);
                        break;
                    }
                }
            }
            Object.entries(fileGroups).forEach(([prefix, groupFiles]) => {
                if (groupFiles.length <= 5) return;
                const sorted = groupFiles.map(name => ({
                    name, path: path.join(sessionPath, name),
                    mtime: fs.statSync(path.join(sessionPath, name)).mtime.getTime()
                })).sort((a, b) => b.mtime - a.mtime);
                sorted.slice(5).forEach(file => {
                    try { fs.unlinkSync(file.path); } catch (e) {}
                });
            });
        } catch (err) {}
    });
}
setInterval(cleanupSessionKeys, 5 * 60 * 1000);
setTimeout(cleanupSessionKeys, 30000);

// ===================================================
// TASK FOLDER MANAGEMENT
// ===================================================
function createTaskFolder(taskId, taskInfo) {
    const taskFolder = path.join(__dirname, 'tasks', taskId);
    try {
        if (!fs.existsSync(taskFolder)) fs.mkdirSync(taskFolder, { recursive: true });
        const metadata = {
            taskId: taskInfo.taskId,
            sessionId: taskInfo.sessionId,
            target: taskInfo.target,
            targetType: taskInfo.targetType,
            prefix: taskInfo.prefix,
            delaySec: taskInfo.delaySec,
            taskType: taskInfo.taskType || 'message',
            totalMessages: taskInfo.totalMessages || 0,
            mentionType: taskInfo.mentionType || 'none',
            mentionNumbers: taskInfo.mentionNumbers || [],
            createdAt: taskInfo.createdAt,
            startTime: taskInfo.startTime,
            migratedFrom: taskInfo.migratedFrom || null,
            status: 'running',
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(path.join(taskFolder, 'metadata.json'), JSON.stringify(metadata, null, 2));
        if (taskInfo.messages && taskInfo.messages.length > 0) {
            fs.writeFileSync(path.join(taskFolder, 'messages.txt'), taskInfo.messages.join('\n'));
        }
        if (taskInfo.imagePath) {
            fs.writeFileSync(path.join(taskFolder, 'image_info.json'), JSON.stringify({ imagePath: taskInfo.imagePath }, null, 2));
        }
        return taskFolder;
    } catch (error) {
        logError(`Failed to create task folder ${taskId}: ${error.message}`);
        return null;
    }
}

function updateTaskMetadata(taskId, updates) {
    const metadataPath = path.join(__dirname, 'tasks', taskId, 'metadata.json');
    try {
        if (fs.existsSync(metadataPath)) {
            const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
            const updated = { ...metadata, ...updates, lastUpdated: new Date().toISOString() };
            fs.writeFileSync(metadataPath, JSON.stringify(updated, null, 2));
        }
    } catch (error) {}
}

function deleteTaskFolder(taskId) {
    const taskFolder = path.join(__dirname, 'tasks', taskId);
    try { if (fs.existsSync(taskFolder)) fs.rmSync(taskFolder, { recursive: true, force: true }); }
    catch (error) {}
}

// ===================================================
// CLEANUP FUNCTIONS
// ===================================================
function completeSessionCleanup(sessionId) {
    logInfo(`🗑️ COMPLETE cleanup for session: ${sessionId}`);
    manuallyDisconnectedSessions.add(sessionId);

    // Unlink from remote backup
    if (remoteBackupLinks.has(sessionId)) {
        const backupId = remoteBackupLinks.get(sessionId);
        const backupInfo = activeClients.get(backupId);
        if (backupInfo) {
            backupInfo.isRemoteBackup = false;
            delete backupInfo.primarySessionId;
            backupInfo.backupActive = false;
        }
        remoteBackupLinks.delete(sessionId);
    }
    for (const [p, b] of remoteBackupLinks.entries()) {
        if (b === sessionId) {
            const pInfo = activeClients.get(p);
            if (pInfo) delete pInfo.remoteBackupSessionId;
            remoteBackupLinks.delete(p);
            break;
        }
    }

    const clientInfo = activeClients.get(sessionId);
    if (!clientInfo) return;

    if (clientInfo.tasks) {
        clientInfo.tasks.forEach(task => {
            task.stopRequested = true;
            task.isSending = false;
            task.endTime = new Date();
            if (taskRunningLocks.has(task.taskId)) taskRunningLocks.delete(task.taskId);
            if (taskLogs.has(task.taskId)) taskLogs.delete(task.taskId);
            deleteTaskFolder(task.taskId);
        });
    }

    if (clientInfo.client) {
        try { clientInfo.client.end(); } catch (error) {}
    }

    if (sessionRestartAttempts.has(sessionId)) sessionRestartAttempts.delete(sessionId);
    if (pairCodeSessions.has(sessionId)) pairCodeSessions.delete(sessionId);

    if (clientInfo.authPath && fs.existsSync(clientInfo.authPath)) {
        try { fs.rmSync(clientInfo.authPath, { recursive: true, force: true }); } catch (error) {}
    }

    activeClients.delete(sessionId);
    if (userSessions.has(sessionId)) userSessions.delete(sessionId);
    savePersistentData();
    logSuccess(`✅ Session cleaned: ${sessionId}`);
}

function completeTaskCleanup(sessionId, taskId) {
    const clientInfo = activeClients.get(sessionId);
    if (!clientInfo) return;
    const taskInfo = clientInfo.tasks.find(t => t.taskId === taskId);
    if (!taskInfo) return;
    taskInfo.stopRequested = true;
    taskInfo.isSending = false;
    taskInfo.endTime = new Date();
    if (taskRunningLocks.has(taskId)) taskRunningLocks.delete(taskId);
    if (taskLogs.has(taskId)) taskLogs.delete(taskId);
    deleteTaskFolder(taskId);
    clientInfo.tasks = clientInfo.tasks.filter(t => t.taskId !== taskId);
    savePersistentData();
    logSuccess(`✅ Task cleaned: ${taskId}`);
}

function checkPairCodeTimeouts() {
    const now = Date.now();
    const TIMEOUT_MS = 10 * 60 * 1000;
    pairCodeSessions.forEach((info, sessionId) => {
        if (!info.hasConnected && (now - info.createdAt) > TIMEOUT_MS) {
            logWarning(`⏰ Pair code session ${sessionId} timeout`);
            completeSessionCleanup(sessionId);
        }
    });
}
setInterval(checkPairCodeTimeouts, 2 * 60 * 1000);

// ===================================================
// 🔥 REMOTE BACKUP CORE SYSTEM
// ===================================================
function findPrimaryForBackup(backupSessionId) {
    for (const [primaryId, backupId] of remoteBackupLinks.entries()) {
        if (backupId === backupSessionId) return primaryId;
    }
    return null;
}

async function activateRemoteBackup(primarySessionId, reason = "primary_disconnected") {
    const backupSessionId = remoteBackupLinks.get(primarySessionId);
    if (!backupSessionId) return;

    const primaryInfo = activeClients.get(primarySessionId);
    const backupInfo = activeClients.get(backupSessionId);

    if (!backupInfo) {
        logError(`❌ Backup session ${backupSessionId} not found`);
        return;
    }
    if (backupInfo.backupActive) {
        logWarning(`⚠️ Backup ${backupSessionId} already active`);
        return;
    }
    if (!backupInfo.isConnected) {
        logWarning(`⏳ Backup ${backupSessionId} not connected. Setting pendingActivation.`);
        backupInfo.pendingActivation = true;
        backupInfo.pendingFor = primarySessionId;
        return;
    }

    logSuccess(`🔥🔥🔥 ACTIVATING REMOTE BACKUP [${reason}]: ${backupSessionId} for ${primarySessionId}`);
    backupInfo.backupActive = true;
    backupInfo.backupActiveFor = primarySessionId;

    const activeTasks = (primaryInfo?.tasks || []).filter(t => t.isSending && !t.stopRequested);
    if (activeTasks.length === 0) {
        logWarning(`⚠️ No active tasks to migrate`);
        backupInfo.backupActive = true;
        savePersistentData();
        return;
    }

    logInfo(`📦 Migrating ${activeTasks.length} task(s)`);
    for (const task of activeTasks) {
        task.stopRequested = true;
        task.isSending = false;
        task.endTime = new Date();
        if (taskRunningLocks.has(task.taskId)) taskRunningLocks.delete(task.taskId);

        const newTaskId = generateShortTaskId();
        const newTask = {
            taskId: newTaskId,
            sessionId: backupSessionId,
            target: task.target,
            targetType: task.targetType,
            messages: task.messages ? [...task.messages] : [],
            delaySec: task.delaySec,
            prefix: task.prefix || "",
            taskType: task.taskType || 'message',
            imagePath: task.imagePath || null,
            isSending: true,
            stopRequested: false,
            totalMessages: task.totalMessages || 0,
            sentMessages: task.sentMessages || 0,
            currentMessageIndex: task.currentMessageIndex || 0,
            startTime: new Date(),
            createdAt: new Date().toISOString(),
            logs: [],
            mentionType: task.mentionType || 'none',
            mentionNumbers: task.mentionNumbers || [],
            migratedFrom: primarySessionId,
            migratedFromTaskId: task.taskId,
            migrationReason: reason,
            migrationTime: new Date().toISOString()
        };

        if (!backupInfo.tasks) backupInfo.tasks = [];
        backupInfo.tasks.push(newTask);
        taskLogs.set(newTaskId, [{
            type: "success",
            message: `<i class="fas fa-exchange-alt"></i> [${new Date().toLocaleString()}] Migrated from primary (${reason})`,
            details: `Primary: ${primarySessionId} | Backup: ${backupSessionId} | From msg #${newTask.sentMessages + 1}`,
            timestamp: new Date()
        }]);
        createTaskFolder(newTaskId, newTask);
        logSuccess(`📦 Migrated task ${task.taskId} → ${newTaskId}`);

        setTimeout(() => {
            if (!activeClients.has(backupSessionId)) return;
            const bi = activeClients.get(backupSessionId);
            const ti = bi.tasks.find(t => t.taskId === newTaskId);
            if (!ti || ti.stopRequested || taskRunningLocks.get(newTaskId)) return;
            if (ti.taskType === 'image') sendImagesLoop(backupSessionId, newTaskId);
            else sendMessagesLoop(backupSessionId, newTaskId);
        }, 2000);
    }
    backupInfo.lastActivity = Date.now();
    savePersistentData();
    logSuccess(`✅✅✅ REMOTE BACKUP ACTIVE`);
}

function deactivateRemoteBackup(primarySessionId) {
    const backupSessionId = remoteBackupLinks.get(primarySessionId);
    if (!backupSessionId) return;
    const backupInfo = activeClients.get(backupSessionId);
    if (!backupInfo) return;
    if (!backupInfo.backupActive) {
        backupInfo.pendingActivation = false;
        return;
    }
    logInfo(`🔄 Primary ${primarySessionId} back. Deactivating backup ${backupSessionId}`);
    (backupInfo.tasks || []).forEach(task => {
        if (task.migratedFrom === primarySessionId) {
            task.stopRequested = true;
            task.isSending = false;
            task.endTime = new Date();
            if (taskRunningLocks.has(task.taskId)) taskRunningLocks.delete(task.taskId);
        }
    });
    backupInfo.backupActive = false;
    backupInfo.backupActiveFor = null;
    savePersistentData();
    logSuccess(`✅ Backup deactivated`);
}

function handleBackupOnline(backupSessionId) {
    const backupInfo = activeClients.get(backupSessionId);
    if (!backupInfo) return;
    if (backupInfo.pendingActivation && backupInfo.pendingFor) {
        logInfo(`⏳ Backup online. Activating pending failover...`);
        const primaryId = backupInfo.pendingFor;
        backupInfo.pendingActivation = false;
        backupInfo.pendingFor = null;
        setTimeout(() => activateRemoteBackup(primaryId, "backup_came_online"), 3000);
    }
}

function checkFailoverStatus() {
    for (const [primaryId, backupId] of remoteBackupLinks.entries()) {
        const primaryInfo = activeClients.get(primaryId);
        const backupInfo = activeClients.get(backupId);
        if (!primaryInfo || !backupInfo) continue;
        const primaryDown = !primaryInfo.isConnected || manuallyDisconnectedSessions.has(primaryId);
        const hasActiveTasks = (primaryInfo.tasks || []).some(t => t.isSending && !t.stopRequested);
        if (primaryDown && hasActiveTasks && !backupInfo.backupActive) {
            logWarning(`🔍 Failover check: Primary ${primaryId} down. Activating backup.`);
            activateRemoteBackup(primaryId, "auto_check");
        }
        if (!primaryDown && backupInfo.backupActive) {
            logInfo(`🔍 Primary up. Deactivating backup.`);
            deactivateRemoteBackup(primaryId);
        }
    }
}
setInterval(checkFailoverStatus, 15 * 1000);

// ===================================================
// SESSION RECOVERY
// ===================================================
async function recoverSession(sessionId, clientInfo) {
    if (manuallyDisconnectedSessions.has(sessionId)) {
        if (remoteBackupLinks.has(sessionId)) {
            activateRemoteBackup(sessionId, "primary_manually_stopped");
        }
        return null;
    }
    try {
        const attempts = sessionRestartAttempts.get(sessionId) || 0;
        sessionRestartAttempts.set(sessionId, attempts + 1);

        const { state, saveCreds } = await useMultiFileAuthState(clientInfo.authPath);
        const { version } = await fetchLatestBaileysVersion();

        const waClient = makeWASocket({
            version,
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" }))
            },
            printQRInTerminal: false,
            logger: pino({ level: "silent" }),
            browser: Browsers.ubuntu('Chrome'),
            syncFullHistory: false,
            generateHighQualityLinkPreview: true,
            shouldIgnoreJid: jid => isJidBroadcast(jid),
            getMessage: async () => ({}),
            markOnlineOnConnect: false,
            retryRequestDelayMs: 1000,
            maxRetries: 1000000000,
            connectTimeoutMs: 60000
        });

        clientInfo.client = waClient;
        clientInfo.isConnected = false;
        activeClients.set(sessionId, clientInfo);

        waClient.ev.on("creds.update", saveCreds);
        waClient.ev.on("connection.update", async (update) => {
            const { connection, lastDisconnect } = update;
            if (manuallyDisconnectedSessions.has(sessionId)) {
                try { waClient.end(); } catch (e) {}
                return;
            }

            if (connection === "open") {
                logSuccess(`✅ Session ${sessionId} CONNECTED`);
                clientInfo.isConnected = true;
                clientInfo.lastActivity = Date.now();
                sessionRestartAttempts.set(sessionId, 0);
                if (pairCodeSessions.has(sessionId)) pairCodeSessions.get(sessionId).hasConnected = true;

                if (remoteBackupLinks.has(sessionId)) deactivateRemoteBackup(sessionId);
                if (clientInfo.isRemoteBackup) {
                    handleBackupOnline(sessionId);
                    const primaryId = clientInfo.primarySessionId;
                    if (primaryId) {
                        const primaryInfo = activeClients.get(primaryId);
                        if (!primaryInfo || !primaryInfo.isConnected) {
                            activateRemoteBackup(primaryId, "backup_online_primary_down");
                        }
                    }
                }
                if (clientInfo.tasks && clientInfo.tasks.length > 0) {
                    clientInfo.tasks.forEach(task => {
                        if (task.isSending && !task.stopRequested && !taskRunningLocks.get(task.taskId)) {
                            resumeTask(sessionId, task.taskId);
                        }
                    });
                }
            }
            else if (connection === "close") {
                clientInfo.isConnected = false;
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                logWarning(`⚠️ Session ${sessionId} closed. Code: ${statusCode}`);
                if (manuallyDisconnectedSessions.has(sessionId)) return;

                if (remoteBackupLinks.has(sessionId)) {
                    logWarning(`🚨 PRIMARY ${sessionId} DOWN! Failover...`);
                    setTimeout(() => activateRemoteBackup(sessionId, "primary_close_" + statusCode), 3000);
                }
                if (statusCode === 401) {
                    logError(`❌ Session ${sessionId} LOGGED OUT`);
                    if (remoteBackupLinks.has(sessionId)) {
                        await activateRemoteBackup(sessionId, "primary_logged_out");
                    }
                    completeSessionCleanup(sessionId);
                    return;
                }
                const delayTime = Math.min(1000 * Math.pow(2, Math.min(attempts, 10)), 30000);
                setTimeout(() => {
                    if (!manuallyDisconnectedSessions.has(sessionId)) {
                        recoverSession(sessionId, clientInfo);
                    }
                }, delayTime);
            }
        });
        return waClient;
    } catch (error) {
        logError(`Failed recover ${sessionId}: ${error.message}`);
        if (manuallyDisconnectedSessions.has(sessionId)) return null;
        const attempts = sessionRestartAttempts.get(sessionId) || 0;
        const delayTime = Math.min(5000 * Math.pow(2, Math.min(attempts, 10)), 60000);
        setTimeout(() => {
            if (!manuallyDisconnectedSessions.has(sessionId)) recoverSession(sessionId, clientInfo);
        }, delayTime);
        return null;
    }
}

async function resumeTask(sessionId, taskId) {
    const clientInfo = activeClients.get(sessionId);
    if (!clientInfo) return;
    const taskInfo = clientInfo.tasks.find(t => t.taskId === taskId);
    if (!taskInfo || !taskInfo.isSending || taskInfo.stopRequested) return;
    if (taskRunningLocks.get(taskId)) return;

    const logs = taskLogs.get(taskId) || [];
    logs.unshift({
        type: "info",
        message: `<i class="fas fa-sync-alt"></i> [${new Date().toLocaleString()}] Task resumed`,
        details: `Continuing from message ${taskInfo.sentMessages + 1}`,
        timestamp: new Date()
    });
    taskLogs.set(taskId, logs);

    while (!clientInfo.isConnected && taskInfo.isSending && !taskInfo.stopRequested) {
        await delay(5000);
    }
    if (clientInfo.isConnected && taskInfo.isSending && !taskInfo.stopRequested && !taskRunningLocks.get(taskId)) {
        if (taskInfo.taskType === 'image') sendImagesLoop(sessionId, taskId);
        else sendMessagesLoop(sessionId, taskId);
    }
}

setInterval(() => {
    const now = Date.now();
    for (let [sessionId, clientInfo] of activeClients.entries()) {
        if (manuallyDisconnectedSessions.has(sessionId)) continue;
        if (clientInfo.lastActivity && (now - clientInfo.lastActivity > 48 * 60 * 60 * 1000)) {
            logInfo(`Cleaning inactive: ${sessionId}`);
            completeSessionCleanup(sessionId);
        }
    }
    for (let [sessionId, clientInfo] of activeClients.entries()) {
        if (manuallyDisconnectedSessions.has(sessionId)) continue;
        if (!clientInfo.isConnected && clientInfo.client) {
            const hasActiveTasks = clientInfo.tasks && clientInfo.tasks.some(t => t.isSending);
            if (hasActiveTasks && !remoteBackupLinks.has(sessionId)) {
                recoverSession(sessionId, clientInfo);
            }
        }
    }
    savePersistentData();
    optimizeMemory();
}, 5 * 60 * 1000);

setInterval(savePersistentData, 2 * 60 * 1000);

// ===================================================
// HEALTH / API STATUS
// ===================================================
app.get("/health", (req, res) => {
    const memoryUsage = process.memoryUsage();
    const uptime = Date.now() - SERVER_START_TIME;
    res.json({
        status: "RUNNING",
        uptime: formatUptime(uptime),
        memory: {
            used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + "MB",
            total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + "MB"
        },
        sessions: activeClients.size,
        remoteBackups: remoteBackupLinks.size,
        activeBackups: Array.from(activeClients.values()).filter(c => c.backupActive).length,
        tasks: Array.from(activeClients.values()).reduce((sum, client) => sum + (client.tasks ? client.tasks.length : 0), 0),
        activeTasks: Array.from(activeClients.values()).reduce((sum, client) => sum + (client.tasks ? client.tasks.filter(t => t.isSending).length : 0), 0),
        timestamp: new Date().toISOString()
    });
});

app.get("/api/live-status", requireAuth, (req, res) => {
    const { sessionId } = req.query;
    const user = req.user;
    if (!sessionId || !activeClients.has(sessionId)) return res.json({ error: "Invalid session" });
    const clientInfo = activeClients.get(sessionId);
    if (clientInfo.userId !== user.userId) return res.json({ error: "Access denied" });

    const runningTasksCount = clientInfo.tasks ? clientInfo.tasks.filter(t => t.isSending).length : 0;
    const tasksStatus = clientInfo.tasks ? clientInfo.tasks.map(task => ({
        taskId: task.taskId,
        target: task.target,
        targetType: task.targetType,
        taskType: task.taskType || 'message',
        isSending: task.isSending,
        sentMessages: task.sentMessages,
        totalMessages: task.totalMessages,
        currentIndex: task.currentMessageIndex || 0,
        createdAt: task.createdAt,
        createdAtFormatted: task.createdAt ? formatDate(task.createdAt) : null,
        migratedFrom: task.migratedFrom || null
    })) : [];

    res.json({
        isConnected: clientInfo.isConnected,
        number: clientInfo.number,
        tasks: tasksStatus,
        runningTasksCount,
        lastActivity: clientInfo.lastActivity,
        createdAt: clientInfo.createdAt,
        createdAtFormatted: clientInfo.createdAt ? formatDate(clientInfo.createdAt) : null,
        isRemoteBackup: clientInfo.isRemoteBackup || false,
        backupActive: clientInfo.backupActive || false,
        backupActiveFor: clientInfo.backupActiveFor || null,
        remoteBackupSessionId: clientInfo.remoteBackupSessionId || null,
        primarySessionId: clientInfo.primarySessionId || null,
        pendingActivation: clientInfo.pendingActivation || false
    });
});

app.get("/api/live-logs", requireAuth, (req, res) => {
    const { sessionId, taskId } = req.query;
    const user = req.user;
    if (!sessionId || !activeClients.has(sessionId) || !taskLogs.has(taskId))
        return res.json({ error: "Invalid session or task" });
    const clientInfo = activeClients.get(sessionId);
    if (clientInfo.userId !== user.userId) return res.json({ error: "Access denied" });
    const logs = taskLogs.get(taskId) || [];
    const taskInfo = clientInfo.tasks.find(t => t.taskId === taskId);
    res.json({
        logs: logs.slice(0, 50),
        taskInfo: taskInfo ? {
            isSending: taskInfo.isSending,
            sentMessages: taskInfo.sentMessages,
            totalMessages: taskInfo.totalMessages,
            taskType: taskInfo.taskType || 'message',
            createdAt: taskInfo.createdAt,
            createdAtFormatted: taskInfo.createdAt ? formatDate(taskInfo.createdAt) : null
        } : null
    });
});

app.get("/api/get-numbers", requireAuth, (req, res) => {
    const user = req.user;
    const numbers = new Map();
    activeClients.forEach((clientInfo, sessionId) => {
        if (clientInfo.userId === user.userId) {
            if (!numbers.has(clientInfo.number)) numbers.set(clientInfo.number, []);
            const runningTasksCount = clientInfo.tasks ? clientInfo.tasks.filter(t => t.isSending).length : 0;
            numbers.get(clientInfo.number).push({
                sessionId,
                isConnected: clientInfo.isConnected,
                runningTasksCount,
                createdAt: clientInfo.createdAt,
                createdAtFormatted: clientInfo.createdAt ? formatDate(clientInfo.createdAt) : null,
                isRemoteBackup: clientInfo.isRemoteBackup || false,
                backupActive: clientInfo.backupActive || false,
                remoteBackupSessionId: clientInfo.remoteBackupSessionId || null,
                primarySessionId: clientInfo.primarySessionId || null
            });
        }
    });
    res.json(Array.from(numbers.entries()).map(([number, sessions]) => ({ number, sessions })));
});

// 🔥 All my sessions with backup info
app.get("/api/my-sessions", requireAuth, (req, res) => {
    const user = req.user;
    const list = [];
    activeClients.forEach((clientInfo, sessionId) => {
        if (clientInfo.userId === user.userId) {
            list.push({
                sessionId,
                number: clientInfo.number,
                isConnected: clientInfo.isConnected,
                runningTasksCount: clientInfo.tasks ? clientInfo.tasks.filter(t => t.isSending).length : 0,
                totalTasks: clientInfo.tasks ? clientInfo.tasks.length : 0,
                tasks: clientInfo.tasks ? clientInfo.tasks.map(t => ({
                    taskId: t.taskId,
                    isSending: t.isSending,
                    taskType: t.taskType,
                    target: t.target,
                    sentMessages: t.sentMessages
                })) : [],
                createdAt: clientInfo.createdAt,
                createdAtFormatted: clientInfo.createdAt ? formatDate(clientInfo.createdAt) : null,
                isRemoteBackup: clientInfo.isRemoteBackup || false,
                backupActive: clientInfo.backupActive || false,
                backupActiveFor: clientInfo.backupActiveFor || null,
                remoteBackupSessionId: clientInfo.remoteBackupSessionId || null,
                primarySessionId: clientInfo.primarySessionId || null,
                pendingActivation: clientInfo.pendingActivation || false
            });
        }
    });
    res.json({ success: true, sessions: list, links: Array.from(remoteBackupLinks.entries()) });
});

// ===================================================
// 🔥 REMOTE BACKUP ENDPOINTS
// ===================================================
app.post("/api/remote-backup/link", requireAuth, (req, res) => {
    const { primarySessionId, backupSessionId } = req.body;
    const user = req.user;
    if (!primarySessionId || !backupSessionId) return res.json({ success: false, error: "Both session IDs required" });
    if (primarySessionId === backupSessionId) return res.json({ success: false, error: "Cannot link to self" });
    if (!activeClients.has(primarySessionId) || !activeClients.has(backupSessionId))
        return res.json({ success: false, error: "Invalid session ID" });

    const primaryInfo = activeClients.get(primarySessionId);
    const backupInfo = activeClients.get(backupSessionId);
    if (primaryInfo.userId !== user.userId || backupInfo.userId !== user.userId)
        return res.json({ success: false, error: "Access denied" });

    if (primaryInfo.remoteBackupSessionId) remoteBackupLinks.delete(primarySessionId);
    if (backupInfo.primarySessionId) remoteBackupLinks.delete(backupInfo.primarySessionId);

    remoteBackupLinks.set(primarySessionId, backupSessionId);
    primaryInfo.remoteBackupSessionId = backupSessionId;
    backupInfo.primarySessionId = primarySessionId;
    backupInfo.isRemoteBackup = true;
    savePersistentData();
    logSuccess(`🔗 Remote backup linked: ${primarySessionId} ↔ ${backupSessionId}`);

    if (!primaryInfo.isConnected && primaryInfo.tasks?.some(t => t.isSending)) {
        setTimeout(() => activateRemoteBackup(primarySessionId, "linked_primary_down"), 2000);
    }
    res.json({ success: true, message: "Remote backup linked successfully" });
});

app.post("/api/remote-backup/unlink", requireAuth, (req, res) => {
    const { primarySessionId } = req.body;
    const user = req.user;
    if (!primarySessionId || !activeClients.has(primarySessionId)) return res.json({ success: false, error: "Invalid session" });
    const primaryInfo = activeClients.get(primarySessionId);
    if (primaryInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });

    const backupId = remoteBackupLinks.get(primarySessionId);
    if (backupId && activeClients.has(backupId)) {
        const backupInfo = activeClients.get(backupId);
        backupInfo.isRemoteBackup = false;
        delete backupInfo.primarySessionId;
        backupInfo.backupActive = false;
        backupInfo.pendingActivation = false;
    }
    delete primaryInfo.remoteBackupSessionId;
    remoteBackupLinks.delete(primarySessionId);
    savePersistentData();
    logSuccess(`🔓 Remote backup unlinked: ${primarySessionId}`);
    res.json({ success: true, message: "Backup unlinked" });
});

app.post("/api/remote-backup/activate", requireAuth, async (req, res) => {
    const { primarySessionId } = req.body;
    const user = req.user;
    if (!primarySessionId || !activeClients.has(primarySessionId)) return res.json({ success: false, error: "Invalid session" });
    const primaryInfo = activeClients.get(primarySessionId);
    if (primaryInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });
    await activateRemoteBackup(primarySessionId, "manual_activation");
    res.json({ success: true, message: "Backup activation triggered" });
});

app.post("/api/remote-backup/deactivate", requireAuth, (req, res) => {
    const { primarySessionId } = req.body;
    const user = req.user;
    if (!primarySessionId || !activeClients.has(primarySessionId)) return res.json({ success: false, error: "Invalid session" });
    const primaryInfo = activeClients.get(primarySessionId);
    if (primaryInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });
    deactivateRemoteBackup(primarySessionId);
    res.json({ success: true, message: "Backup deactivated" });
});

app.get("/api/remote-backup/status", requireAuth, (req, res) => {
    const user = req.user;
    const status = [];
    for (const [primaryId, backupId] of remoteBackupLinks.entries()) {
        const p = activeClients.get(primaryId);
        const b = activeClients.get(backupId);
        if (!p || !b) continue;
        if (p.userId !== user.userId) continue;
        status.push({
            primarySessionId: primaryId,
            primaryNumber: p.number,
            primaryConnected: p.isConnected,
            primaryTasks: (p.tasks || []).filter(t => t.isSending).length,
            backupSessionId: backupId,
            backupNumber: b.number,
            backupConnected: b.isConnected,
            backupActive: b.backupActive || false,
            pendingActivation: b.pendingActivation || false
        });
    }
    res.json({ success: true, backups: status });
});

// ===================================================
// 🔑 APPROVAL KEY ENDPOINTS
// ===================================================
app.post("/api/generate-approval-key", (req, res) => {
    try {
        const fingerprint = req.body || {};
        const approvalKey = generateApprovalKey(fingerprint);
        const approvals = loadApprovals();
        if (!approvals[approvalKey]) {
            approvals[approvalKey] = {
                approvalKey,
                fingerprint,
                status: 'pending',
                createdAt: new Date().toISOString(),
                approvedAt: null,
                rejectedAt: null,
                lastChecked: null,
                ip: req.ip || req.connection?.remoteAddress || 'unknown'
            };
            saveApprovals(approvals);
            logInfo(`🔑 New approval key: ${approvalKey}`);
        } else {
            approvals[approvalKey].lastChecked = new Date().toISOString();
            saveApprovals(approvals);
        }
        res.json({
            ok: true,
            approvalKey,
            status: approvals[approvalKey].status
        });
    } catch (error) {
        logError('generate-approval-key error: ' + error.message);
        res.json({ ok: false, error: error.message });
    }
});

app.post("/api/check-approval", (req, res) => {
    try {
        const { approvalKey } = req.body || {};
        if (!approvalKey) return res.json({ ok: false, error: "approvalKey required" });

        const approvals = loadApprovals();
        const entry = approvals[approvalKey];

        if (isAdminRequest(req)) {
            if (!entry) {
                approvals[approvalKey] = {
                    approvalKey,
                    fingerprint: {},
                    status: 'approved',
                    createdAt: new Date().toISOString(),
                    approvedAt: new Date().toISOString(),
                    autoApprovedByAdmin: true
                };
            } else if (entry.status !== 'approved') {
                entry.status = 'approved';
                entry.approvedAt = new Date().toISOString();
                entry.autoApprovedByAdmin = true;
            } else {
                entry.lastChecked = new Date().toISOString();
            }
            saveApprovals(approvals);
            return res.json({ ok: true, approved: true, status: 'approved', admin: true });
        }

        if (!entry) return res.json({ ok: true, approved: false, status: 'unknown', error: 'Key not found' });

        entry.lastChecked = new Date().toISOString();
        saveApprovals(approvals);
        res.json({
            ok: true,
            approved: entry.status === 'approved',
            status: entry.status,
            createdAt: entry.createdAt,
            approvedAt: entry.approvedAt || null
        });
    } catch (error) {
        logError('check-approval error: ' + error.message);
        res.json({ ok: false, error: error.message });
    }
});

// Admin approval management
app.get("/api/admin/approval-keys", requireAdmin, (req, res) => {
    const approvals = loadApprovals();
    const list = Object.values(approvals).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({
        ok: true,
        total: list.length,
        pending: list.filter(x => x.status === 'pending').length,
        approved: list.filter(x => x.status === 'approved').length,
        rejected: list.filter(x => x.status === 'rejected').length,
        keys: list
    });
});

app.post("/api/admin/approve-key", requireAdmin, (req, res) => {
    const { approvalKey } = req.body || {};
    if (!approvalKey) return res.json({ ok: false, error: "approvalKey required" });
    const approvals = loadApprovals();
    if (!approvals[approvalKey]) {
        approvals[approvalKey] = {
            approvalKey,
            fingerprint: {},
            status: 'approved',
            createdAt: new Date().toISOString(),
            approvedAt: new Date().toISOString()
        };
    } else {
        approvals[approvalKey].status = 'approved';
        approvals[approvalKey].approvedAt = new Date().toISOString();
        approvals[approvalKey].rejectedAt = null;
    }
    saveApprovals(approvals);
    logSuccess(`✅ Approval granted: ${approvalKey}`);
    res.json({ ok: true, message: "Key approved" });
});

app.post("/api/admin/reject-key", requireAdmin, (req, res) => {
    const { approvalKey } = req.body || {};
    if (!approvalKey) return res.json({ ok: false, error: "approvalKey required" });
    const approvals = loadApprovals();
    if (approvals[approvalKey]) {
        approvals[approvalKey].status = 'rejected';
        approvals[approvalKey].rejectedAt = new Date().toISOString();
        saveApprovals(approvals);
        logWarning(`❌ Approval rejected: ${approvalKey}`);
    }
    res.json({ ok: true, message: "Key rejected" });
});

app.post("/api/admin/delete-key", requireAdmin, (req, res) => {
    const { approvalKey } = req.body || {};
    if (!approvalKey) return res.json({ ok: false, error: "approvalKey required" });
    const approvals = loadApprovals();
    if (approvals[approvalKey]) {
        delete approvals[approvalKey];
        saveApprovals(approvals);
        logInfo(`🗑️ Approval key deleted: ${approvalKey}`);
    }
    res.json({ ok: true, message: "Key deleted" });
});

// ===================================================
// ADMIN SESSION APIS
// ===================================================
app.get("/api/admin/all-sessions", requireAdmin, (req, res) => {
    const allSessions = [];
    activeClients.forEach((clientInfo, sessionId) => {
        allSessions.push({
            sessionId,
            number: clientInfo.number,
            isConnected: clientInfo.isConnected,
            userId: clientInfo.userId,
            username: clientInfo.username,
            tasksCount: clientInfo.tasks ? clientInfo.tasks.length : 0,
            activeTasksCount: clientInfo.tasks ? clientInfo.tasks.filter(t => t.isSending).length : 0,
            lastActivity: clientInfo.lastActivity,
            createdAt: clientInfo.createdAt,
            createdAtFormatted: clientInfo.createdAt ? formatDate(clientInfo.createdAt) : null,
            sessionOwner: clientInfo.username,
            isRemoteBackup: clientInfo.isRemoteBackup || false,
            backupActive: clientInfo.backupActive || false,
            remoteBackupSessionId: clientInfo.remoteBackupSessionId || null
        });
    });
    res.json(allSessions);
});

app.get("/api/admin/session-details", requireAdmin, (req, res) => {
    const { sessionId } = req.query;
    if (!sessionId || !activeClients.has(sessionId)) return res.json({ error: "Invalid session" });
    const clientInfo = activeClients.get(sessionId);
    const tasksStatus = clientInfo.tasks ? clientInfo.tasks.map(task => ({
        taskId: task.taskId, target: task.target, targetType: task.targetType,
        taskType: task.taskType || 'message', isSending: task.isSending,
        sentMessages: task.sentMessages, totalMessages: task.totalMessages,
        currentIndex: task.currentMessageIndex || 0, startTime: task.startTime,
        endTime: task.endTime, createdAt: task.createdAt,
        createdAtFormatted: task.createdAt ? formatDate(task.createdAt) : null,
        taskOwner: clientInfo.username, migratedFrom: task.migratedFrom || null
    })) : [];
    res.json({
        sessionId, isConnected: clientInfo.isConnected, number: clientInfo.number,
        userId: clientInfo.userId, username: clientInfo.username, tasks: tasksStatus,
        lastActivity: clientInfo.lastActivity, createdAt: clientInfo.createdAt,
        createdAtFormatted: clientInfo.createdAt ? formatDate(clientInfo.createdAt) : null,
        sessionOwner: clientInfo.username, isRemoteBackup: clientInfo.isRemoteBackup || false,
        backupActive: clientInfo.backupActive || false, remoteBackupSessionId: clientInfo.remoteBackupSessionId || null,
        primarySessionId: clientInfo.primarySessionId || null
    });
});

app.get("/api/admin/task-logs", requireAdmin, (req, res) => {
    const { taskId } = req.query;
    if (!taskId || !taskLogs.has(taskId)) return res.json({ error: "Invalid task" });
    res.json({ logs: (taskLogs.get(taskId) || []).slice(0, 100) });
});

app.post("/api/admin/delete-session", requireAdmin, (req, res) => {
    const { sessionId } = req.body;
    if (!sessionId || !activeClients.has(sessionId)) return res.json({ success: false, error: "Invalid session" });
    completeSessionCleanup(sessionId);
    res.json({ success: true, message: "Session deleted" });
});

app.post("/api/admin/delete-task", requireAdmin, (req, res) => {
    const { sessionId, taskId } = req.body;
    if (!sessionId || !activeClients.has(sessionId)) return res.json({ success: false, error: "Invalid session" });
    completeTaskCleanup(sessionId, taskId);
    res.json({ success: true, message: "Task deleted" });
});

// ===================================================
// HTML ROUTES
// ===================================================
app.get("/", (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/signup", (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/admin-login", (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/dashboard", requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/admin-dashboard", requireAdmin, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/session-status", requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get("/task-logs", requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ===================================================
// AUTH ENDPOINTS
// ===================================================

// Login (with approval check)
app.post("/login", (req, res) => {
    const { username, password, approvalKey } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username && u.password === hashPassword(password));
    if (!user) return res.json({ success: false, error: "Invalid username or password" });

    // 🔑 Approval check
    if (!approvalKey) {
        return res.json({ success: false, error: "Hardware key missing. Refresh page." });
    }

    const isAdminBypass = req.cookies && req.cookies.adminToken === 'admin_authenticated';
    if (!isAdminBypass) {
        const approvals = loadApprovals();
        const entry = approvals[approvalKey];
        if (!entry) {
            return res.json({ success: false, error: "Hardware key not registered. Contact admin." });
        }
        if (entry.status !== 'approved') {
            return res.json({
                success: false,
                error: entry.status === 'rejected'
                    ? "Hardware key rejected by admin"
                    : "Hardware key not approved yet. Contact admin."
            });
        }
    }

    const sessionToken = generateSessionToken();
    user.sessionToken = sessionToken;
    user.lastLogin = new Date().toISOString();
    user.approvalKey = approvalKey;
    saveUsers(users);
    res.cookie('sessionToken', sessionToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    logSuccess(`✅ Login: ${username} [key: ${approvalKey}]`);
    res.json({ success: true, redirect: '/dashboard' });
});

// Signup (with approval check)
app.post("/signup", (req, res) => {
    const { username, email, password, approvalKey } = req.body;
    const users = loadUsers();

    if (approvalKey) {
        const approvals = loadApprovals();
        const entry = approvals[approvalKey];
        const isAdminBypass = req.cookies && req.cookies.adminToken === 'admin_authenticated';
        if (!isAdminBypass && (!entry || entry.status !== 'approved')) {
            return res.json({ success: false, error: "Hardware key not approved. Contact admin first." });
        }
    }

    if (users.find(u => u.username === username)) {
        return res.json({ success: false, error: "Username already exists" });
    }
    const newUser = {
        userId: generateUserId(),
        username,
        email: email || (username + '@local'),
        password: hashPassword(password),
        createdAt: new Date().toISOString(),
        sessionToken: generateSessionToken(),
        approvalKey: approvalKey || null
    };
    users.push(newUser);
    saveUsers(users);
    res.cookie('sessionToken', newUser.sessionToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    logSuccess(`✅ New user: ${username}`);
    res.json({ success: true, redirect: '/dashboard' });
});

// Admin login (auto-approve own key)
app.post("/admin-login", (req, res) => {
    const { username, password, approvalKey } = req.body;
    if (username === ADMIN_CREDENTIALS.username && password === ADMIN_CREDENTIALS.password) {
        res.cookie('adminToken', 'admin_authenticated', { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

        if (approvalKey) {
            const approvals = loadApprovals();
            if (!approvals[approvalKey]) {
                approvals[approvalKey] = {
                    approvalKey,
                    fingerprint: {},
                    status: 'approved',
                    createdAt: new Date().toISOString(),
                    approvedAt: new Date().toISOString(),
                    autoApprovedByAdmin: true
                };
            } else {
                approvals[approvalKey].status = 'approved';
                approvals[approvalKey].approvedAt = new Date().toISOString();
            }
            saveApprovals(approvals);
            logSuccess(`🔑 Admin auto-approved key: ${approvalKey}`);
        }
        res.json({ success: true, redirect: '/admin-dashboard' });
    } else {
        res.json({ success: false, error: "Invalid admin credentials" });
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie('sessionToken');
    res.clearCookie('adminToken');
    res.redirect('/login');
});

// ===================================================
// PAIRING CODE
// ===================================================
app.post("/generate-pairing-code", requireAuth, async (req, res) => {
    const { number: num, isBackup, primarySessionId } = req.body;
    const user = req.user;
    if (!num) return res.json({ success: false, error: "Phone number is required" });

    try {
        const sessionId = generateSessionId();
        const sessionPath = path.join("temp", sessionId);
        if (!fs.existsSync(sessionPath)) fs.mkdirSync(sessionPath, { recursive: true });

        const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
        const { version } = await fetchLatestBaileysVersion();

        const waClient = makeWASocket({
            version,
            auth: {
                creds: state.creds,
                keys: makeCacheableSignalKeyStore(state.keys, pino({ level: "silent" }))
            },
            printQRInTerminal: false,
            logger: pino({ level: "silent" }),
            browser: Browsers.ubuntu('Chrome'),
            syncFullHistory: false,
            generateHighQualityLinkPreview: true,
            shouldIgnoreJid: jid => isJidBroadcast(jid),
            getMessage: async key => { return {} },
            markOnlineOnConnect: false,
            retryRequestDelayMs: 3000,
            maxRetries: 1000000000,
            connectTimeoutMs: 60000
        });

        if (!waClient.authState.creds.registered) {
            await delay(1500);
            const phoneNumber = num.replace(/[^0-9]/g, "");
            const code = await waClient.requestPairingCode(phoneNumber);

            activeClients.set(sessionId, {
                client: waClient,
                number: num,
                authPath: sessionPath,
                isConnected: false,
                tasks: [],
                lastActivity: Date.now(),
                userId: user.userId,
                username: user.username,
                createdAt: new Date().toISOString(),
                isRemoteBackup: isBackup === true || isBackup === 'true',
                primarySessionId: primarySessionId || null,
                backupActive: false,
                pendingActivation: false
            });

            if (isBackup && primarySessionId && activeClients.has(primarySessionId)) {
                remoteBackupLinks.set(primarySessionId, sessionId);
                const primaryInfo = activeClients.get(primarySessionId);
                primaryInfo.remoteBackupSessionId = sessionId;
                logSuccess(`🔗 Backup ${sessionId} linked to primary ${primarySessionId}`);
            }

            pairCodeSessions.set(sessionId, {
                createdAt: Date.now(),
                hasConnected: false
            });
            logInfo(`🔑 Pair code: ${sessionId} (Backup: ${!!isBackup})`);

            res.json({
                success: true,
                code: code,
                sessionId: sessionId,
                number: num,
                isBackup: !!isBackup
            });
        }

        waClient.ev.on("creds.update", saveCreds);
        waClient.ev.on("connection.update", async (s) => {
            const { connection, lastDisconnect } = s;
            if (manuallyDisconnectedSessions.has(sessionId)) return;

            if (connection === "open") {
                logSuccess(`✅ Connected: ${num} | ${sessionId}`);
                const clientInfo = activeClients.get(sessionId);
                if (clientInfo) {
                    clientInfo.isConnected = true;
                    clientInfo.lastActivity = Date.now();
                    sessionRestartAttempts.set(sessionId, 0);
                    if (pairCodeSessions.has(sessionId)) pairCodeSessions.get(sessionId).hasConnected = true;

                    if (remoteBackupLinks.has(sessionId)) deactivateRemoteBackup(sessionId);
                    if (clientInfo.isRemoteBackup) {
                        handleBackupOnline(sessionId);
                        const pid = clientInfo.primarySessionId;
                        if (pid) {
                            const pInfo = activeClients.get(pid);
                            if (!pInfo || !pInfo.isConnected) activateRemoteBackup(pid, "backup_online");
                        }
                    }
                }
            } else if (connection === "close") {
                const clientInfo = activeClients.get(sessionId);
                if (clientInfo) {
                    clientInfo.isConnected = false;
                    logWarning(`Connection closed: ${sessionId}`);
                    if (manuallyDisconnectedSessions.has(sessionId)) return;
                    const statusCode = lastDisconnect?.error?.output?.statusCode;
                    if (remoteBackupLinks.has(sessionId)) {
                        logWarning(`🚨 Primary down. Failover...`);
                        setTimeout(() => activateRemoteBackup(sessionId, "primary_close_pairing_" + statusCode), 3000);
                    }
                    if (statusCode === 401) {
                        logError(`❌ Logged out: ${sessionId}`);
                        if (remoteBackupLinks.has(sessionId)) {
                            await activateRemoteBackup(sessionId, "primary_logout_pairing");
                        }
                        completeSessionCleanup(sessionId);
                        return;
                    }
                    await delay(10000);
                    recoverSession(sessionId, clientInfo);
                }
            }
        });
    } catch (err) {
        logError("Error in pairing: " + err.message);
        res.json({ success: false, error: err.message });
    }
});

// ===================================================
// MENTION HELPERS
// ===================================================
async function prepareMentions(clientInfo, taskInfo, currentIndex) {
    let activeMentionJids = [];
    let useNativeAllMention = false;
    let mentionLabels = [];

    if (taskInfo.targetType === "group" && taskInfo.mentionType && taskInfo.mentionType !== 'none') {
        const jid = taskInfo.target + "@g.us";
        if (taskInfo.mentionType === 'all_tag') {
            useNativeAllMention = true;
        } else if (taskInfo.mentionType === 'all_group') {
            try {
                const metadata = await clientInfo.client.groupMetadata(jid);
                activeMentionJids = (metadata?.participants || []).map(p => p?.id).filter(Boolean);
            } catch (e) {}
        } else if (taskInfo.mentionNumbers && taskInfo.mentionNumbers.length > 0) {
            activeMentionJids = taskInfo.mentionNumbers.map(n => n + "@s.whatsapp.net");
            if (taskInfo.mentionType === 'single') {
                activeMentionJids = [activeMentionJids[currentIndex % activeMentionJids.length]];
            }
        }
        mentionLabels = activeMentionJids.map(x => String(x).split('@')[0]);
    }
    return { activeMentionJids, useNativeAllMention, mentionLabels };
}

function appendMentionsToText(text, mentionLabels, useNativeAllMention, activeMentionJids) {
    const base = String(text || '').trim();
    if (useNativeAllMention) return base ? `@all ${base}` : '@all';
    if (!activeMentionJids.length) return base;
    const tags = mentionLabels.map(n => '@' + n).join(' ');
    return base ? `${tags} ${base}` : tags;
}

// ===================================================
// SEND MESSAGES LOOP
// ===================================================
async function sendMessagesLoop(sessionId, taskId) {
    if (taskRunningLocks.get(taskId)) return;
    taskRunningLocks.set(taskId, true);

    const clientInfo = activeClients.get(sessionId);
    if (!clientInfo) { taskRunningLocks.delete(taskId); return; }
    const taskInfo = clientInfo.tasks.find(t => t.taskId === taskId);
    if (!taskInfo) { taskRunningLocks.delete(taskId); return; }

    const logs = taskLogs.get(taskId) || [];
    try {
        let index = taskInfo.currentMessageIndex || 0;
        const recipient = taskInfo.targetType === "group"
            ? taskInfo.target + "@g.us"
            : taskInfo.target + "@s.whatsapp.net";

        while (taskInfo.isSending && !taskInfo.stopRequested) {
            optimizeMemory();
            if (!clientInfo.isConnected) {
                logs.unshift({
                    type: "info",
                    message: `<i class="fas fa-hourglass-half"></i> [${new Date().toLocaleString()}] Waiting for connection...`,
                    details: `Auto-resume when connected`,
                    timestamp: new Date()
                });
                if (logs.length > 100) logs.pop();
                taskLogs.set(taskId, logs);
                await delay(10000);
                continue;
            }

            let msg = taskInfo.messages[index];
            if (taskInfo.prefix && taskInfo.prefix.trim() !== "") {
                msg = `${taskInfo.prefix.trim()} ${msg}`;
            }

            const { activeMentionJids, useNativeAllMention, mentionLabels } = await prepareMentions(clientInfo, taskInfo, index);
            const finalMsg = appendMentionsToText(msg, mentionLabels, useNativeAllMention, activeMentionJids);

            const messagePayload = { text: finalMsg };
            if (useNativeAllMention) messagePayload.mentionAll = true;
            else if (activeMentionJids.length) messagePayload.mentions = activeMentionJids;

            const timestamp = new Date().toLocaleString();
            const messageNumber = taskInfo.sentMessages + 1;

            try {
                await clientInfo.client.sendMessage(recipient, messagePayload);
                logs.unshift({
                    type: "success",
                    message: `<i class="fas fa-check-circle"></i> [${timestamp}] Message #${messageNumber} sent`,
                    details: `To: ${taskInfo.target} | "${finalMsg.substring(0, 50)}${finalMsg.length > 50 ? '...' : ''}"`,
                    timestamp: new Date()
                });
                if (logs.length > 100) logs.pop();
                taskLogs.set(taskId, logs);
                logSuccess(`[${sessionId}] Sent #${messageNumber} to ${taskInfo.target}`);

                taskInfo.sentMessages++;
                index = (index + 1) % taskInfo.messages.length;
                taskInfo.currentMessageIndex = index;
                clientInfo.lastActivity = Date.now();
                updateTaskMetadata(taskId, {
                    sentMessages: taskInfo.sentMessages,
                    currentIndex: index,
                    lastActivity: new Date().toISOString()
                });
            } catch (sendError) {
                logs.unshift({
                    type: "error",
                    message: `<i class="fas fa-times-circle"></i> [${timestamp}] Failed #${messageNumber}`,
                    details: `Error: ${sendError.message}`,
                    timestamp: new Date()
                });
                if (logs.length > 100) logs.pop();
                taskLogs.set(taskId, logs);
                logError(`[${sessionId}] Send error: ${sendError.message}`);

                if (sendError.message.includes("connection") ||
                    sendError.message.includes("socket") ||
                    sendError.message.includes("timeout") ||
                    sendError.message.includes("not connected")) {
                    clientInfo.isConnected = false;
                    await delay(5000);
                    continue;
                }
                await delay(taskInfo.delaySec * 1000);
            }

            if (taskInfo.sentMessages % 10 === 0) savePersistentData();
            await delay(taskInfo.delaySec * 1000);
        }

        taskInfo.endTime = new Date();
        taskInfo.isSending = false;
        taskRunningLocks.delete(taskId);
        updateTaskMetadata(taskId, {
            endTime: taskInfo.endTime.toISOString(),
            isSending: false,
            status: taskInfo.stopRequested ? 'stopped' : 'completed'
        });
        logs.unshift({
            type: "info",
            message: `<i class="fas fa-info-circle"></i> [${new Date().toLocaleString()}] Task ${taskInfo.stopRequested ? 'stopped' : 'completed'}`,
            details: `Total sent: ${taskInfo.sentMessages}`,
            timestamp: new Date()
        });
        taskLogs.set(taskId, logs);
    } catch (error) {
        logError(`Critical task error ${taskId}: ${error.message}`);
        logs.unshift({
            type: "error",
            message: `<i class="fas fa-times-circle"></i> [${new Date().toLocaleString()}] Critical error`,
            details: `Error: ${error.message}`,
            timestamp: new Date()
        });
        taskLogs.set(taskId, logs);
        taskInfo.error = error.message;
        taskInfo.isSending = false;
        taskInfo.endTime = new Date();
        taskRunningLocks.delete(taskId);

        if (!taskInfo.stopRequested) {
            setTimeout(() => {
                if (activeClients.has(sessionId)) {
                    const ti = activeClients.get(sessionId).tasks.find(t => t.taskId === taskId);
                    if (ti && !ti.stopRequested && !taskRunningLocks.get(taskId)) {
                        ti.isSending = true;
                        sendMessagesLoop(sessionId, taskId);
                    }
                }
            }, 10000);
        }
    }
}

// ===================================================
// SEND IMAGES LOOP
// ===================================================
async function sendImagesLoop(sessionId, taskId) {
    if (taskRunningLocks.get(taskId)) return;
    taskRunningLocks.set(taskId, true);

    const clientInfo = activeClients.get(sessionId);
    if (!clientInfo) { taskRunningLocks.delete(taskId); return; }
    const taskInfo = clientInfo.tasks.find(t => t.taskId === taskId);
    if (!taskInfo) { taskRunningLocks.delete(taskId); return; }

    const logs = taskLogs.get(taskId) || [];
    try {
        const recipient = taskInfo.targetType === "group"
            ? taskInfo.target + "@g.us"
            : taskInfo.target + "@s.whatsapp.net";

        while (taskInfo.isSending && !taskInfo.stopRequested) {
            optimizeMemory();
            if (!clientInfo.isConnected) {
                logs.unshift({
                    type: "info",
                    message: `<i class="fas fa-hourglass-half"></i> [${new Date().toLocaleString()}] Waiting for connection...`,
                    details: `Auto-resume when connected`,
                    timestamp: new Date()
                });
                if (logs.length > 100) logs.pop();
                taskLogs.set(taskId, logs);
                await delay(10000);
                continue;
            }

            const timestamp = new Date().toLocaleString();
            const imageNumber = taskInfo.sentMessages + 1;

            try {
                const imageBuffer = fs.readFileSync(taskInfo.imagePath);
                let caption = taskInfo.prefix && taskInfo.prefix.trim() !== "" ? taskInfo.prefix.trim() : "";
                const { activeMentionJids, useNativeAllMention, mentionLabels } = await prepareMentions(clientInfo, taskInfo, taskInfo.sentMessages);
                const finalCaption = appendMentionsToText(caption, mentionLabels, useNativeAllMention, activeMentionJids);

                const messageObj = { image: imageBuffer };
                if (finalCaption) messageObj.caption = finalCaption;
                if (useNativeAllMention) messageObj.mentionAll = true;
                else if (activeMentionJids.length) messageObj.mentions = activeMentionJids;

                await clientInfo.client.sendMessage(recipient, messageObj);

                logs.unshift({
                    type: "success",
                    message: `<i class="fas fa-check-circle"></i> [${timestamp}] Image #${imageNumber} sent`,
                    details: `To: ${taskInfo.target}`,
                    timestamp: new Date()
                });
                if (logs.length > 100) logs.pop();
                taskLogs.set(taskId, logs);
                logSuccess(`[${sessionId}] Sent image #${imageNumber}`);

                taskInfo.sentMessages++;
                clientInfo.lastActivity = Date.now();
                updateTaskMetadata(taskId, {
                    sentMessages: taskInfo.sentMessages,
                    lastActivity: new Date().toISOString()
                });
            } catch (sendError) {
                logs.unshift({
                    type: "error",
                    message: `<i class="fas fa-times-circle"></i> [${timestamp}] Image #${imageNumber} failed`,
                    details: `Error: ${sendError.message}`,
                    timestamp: new Date()
                });
                if (logs.length > 100) logs.pop();
                taskLogs.set(taskId, logs);
                logError(`[${sessionId}] Image error: ${sendError.message}`);

                if (sendError.message.includes("connection") ||
                    sendError.message.includes("socket") ||
                    sendError.message.includes("timeout") ||
                    sendError.message.includes("not connected")) {
                    clientInfo.isConnected = false;
                    await delay(5000);
                    continue;
                }
                await delay(taskInfo.delaySec * 1000);
            }

            if (taskInfo.sentMessages % 10 === 0) savePersistentData();
            await delay(taskInfo.delaySec * 1000);
        }

        taskInfo.endTime = new Date();
        taskInfo.isSending = false;
        taskRunningLocks.delete(taskId);
        updateTaskMetadata(taskId, {
            endTime: taskInfo.endTime.toISOString(),
            isSending: false,
            status: taskInfo.stopRequested ? 'stopped' : 'completed'
        });
        logs.unshift({
            type: "info",
            message: `<i class="fas fa-info-circle"></i> [${new Date().toLocaleString()}] Image task ${taskInfo.stopRequested ? 'stopped' : 'completed'}`,
            details: `Total sent: ${taskInfo.sentMessages}`,
            timestamp: new Date()
        });
        taskLogs.set(taskId, logs);
    } catch (error) {
        logError(`Critical image task error ${taskId}: ${error.message}`);
        taskInfo.error = error.message;
        taskInfo.isSending = false;
        taskInfo.endTime = new Date();
        taskRunningLocks.delete(taskId);
        if (!taskInfo.stopRequested) {
            setTimeout(() => {
                if (activeClients.has(sessionId)) {
                    const ti = activeClients.get(sessionId).tasks.find(t => t.taskId === taskId);
                    if (ti && !ti.stopRequested && !taskRunningLocks.get(taskId)) {
                        ti.isSending = true;
                        sendImagesLoop(sessionId, taskId);
                    }
                }
            }, 10000);
        }
    }
}

// ===================================================
// SEND MESSAGE ENDPOINT
// ===================================================
app.post("/send-message", requireAuth, upload.single("messageFile"), async (req, res) => {
    const { target, targetType, delaySec, prefix, selectedSession, mentionType, mentionNumbers } = req.body;
    const user = req.user;

    if (!selectedSession || !activeClients.has(selectedSession))
        return res.json({ success: false, error: "Invalid session selected" });
    const clientInfo = activeClients.get(selectedSession);
    if (clientInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });

    const filePath = req.file?.path;
    const mType = String(mentionType || 'none').toLowerCase();
    const allowedMentionTypes = ['none', 'single', 'all_listed', 'selected_group', 'all_group', 'all_tag'];
    if (!allowedMentionTypes.includes(mType)) return res.json({ success: false, error: "Invalid mention type" });

    const parsedMentionNumbers = mentionNumbers ? mentionNumbers.split(/[,\r\n]+/).map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, '')).filter(Boolean) : [];

    if ((mType === 'single' || mType === 'all_listed' || mType === 'selected_group') && parsedMentionNumbers.length === 0) {
        return res.json({ success: false, error: "Mention numbers required" });
    }
    if ((mType === 'all_group' || mType === 'selected_group' || mType === 'all_tag') && targetType !== "group") {
        return res.json({ success: false, error: "Group mention needs target=group" });
    }
    if (!target || !filePath || !targetType || !delaySec) {
        return res.json({ success: false, error: "Missing required fields" });
    }

    try {
        const messages = fs.readFileSync(filePath, "utf-8").split("\n").filter(msg => msg.trim() !== "");
        if (messages.length === 0) return res.json({ success: false, error: "Message file is empty" });

        const taskId = generateShortTaskId();
        const taskInfo = {
            taskId, sessionId: selectedSession, target, targetType, messages,
            delaySec: parseInt(delaySec), prefix, taskType: 'message',
            isSending: true, stopRequested: false,
            totalMessages: messages.length, sentMessages: 0, currentMessageIndex: 0,
            startTime: new Date(), createdAt: new Date().toISOString(), logs: [],
            mentionType: mType, mentionNumbers: parsedMentionNumbers
        };

        if (!clientInfo.tasks) clientInfo.tasks = [];
        clientInfo.tasks.push(taskInfo);
        clientInfo.lastActivity = Date.now();
        taskLogs.set(taskId, []);
        createTaskFolder(taskId, taskInfo);
        fs.unlinkSync(filePath);

        res.json({ success: true, redirect: `/session-status?sessionId=${selectedSession}` });
        sendMessagesLoop(selectedSession, taskId);
    } catch (error) {
        logError(`[${selectedSession}] Error: ${error.message}`);
        return res.json({ success: false, error: error.message });
    }
});

// ===================================================
// SEND IMAGE ENDPOINT
// ===================================================
app.post("/send-image", requireAuth, upload.single("imageFile"), async (req, res) => {
    const { target, targetType, delaySec, prefix, selectedSession, mentionType, mentionNumbers } = req.body;
    const user = req.user;

    if (!selectedSession || !activeClients.has(selectedSession))
        return res.json({ success: false, error: "Invalid session selected" });
    const clientInfo = activeClients.get(selectedSession);
    if (clientInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });

    const imagePath = req.file?.path;
    const mType = String(mentionType || 'none').toLowerCase();
    const allowedMentionTypes = ['none', 'single', 'all_listed', 'selected_group', 'all_group', 'all_tag'];
    if (!allowedMentionTypes.includes(mType)) return res.json({ success: false, error: "Invalid mention type" });
    const parsedMentionNumbers = mentionNumbers ? mentionNumbers.split(/[,\r\n]+/).map(v => v.trim().replace(/[^\d+]/g, '').replace(/^\+/, '')).filter(Boolean) : [];

    if ((mType === 'single' || mType === 'all_listed' || mType === 'selected_group') && parsedMentionNumbers.length === 0)
        return res.json({ success: false, error: "Mention numbers required" });
    if ((mType === 'all_group' || mType === 'selected_group' || mType === 'all_tag') && targetType !== "group")
        return res.json({ success: false, error: "Group mention needs target=group" });
    if (!target || !imagePath || !targetType || !delaySec)
        return res.json({ success: false, error: "Missing required fields" });

    try {
        const taskId = generateShortTaskId();
        const taskInfo = {
            taskId, sessionId: selectedSession, target, targetType,
            imagePath, delaySec: parseInt(delaySec), prefix, taskType: 'image',
            isSending: true, stopRequested: false, totalMessages: 0, sentMessages: 0,
            startTime: new Date(), createdAt: new Date().toISOString(), logs: [],
            mentionType: mType, mentionNumbers: parsedMentionNumbers
        };
        if (!clientInfo.tasks) clientInfo.tasks = [];
        clientInfo.tasks.push(taskInfo);
        clientInfo.lastActivity = Date.now();
        taskLogs.set(taskId, []);
        createTaskFolder(taskId, taskInfo);

        res.json({ success: true, redirect: `/session-status?sessionId=${selectedSession}` });
        sendImagesLoop(selectedSession, taskId);
    } catch (error) {
        logError(`[${selectedSession}] Error image: ${error.message}`);
        return res.json({ success: false, error: error.message });
    }
});

// ===================================================
// STOP ENDPOINTS
// ===================================================
app.post("/stop-session", requireAuth, (req, res) => {
    const { sessionId } = req.body;
    const user = req.user;
    if (!activeClients.has(sessionId)) return res.json({ success: false, error: "Invalid Session ID" });
    const clientInfo = activeClients.get(sessionId);
    if (clientInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });

    if (remoteBackupLinks.has(sessionId)) {
        const hasActiveTasks = (clientInfo.tasks || []).some(t => t.isSending);
        if (hasActiveTasks) {
            logWarning(`🚨 Manual stop with active tasks → activating backup`);
            activateRemoteBackup(sessionId, "manual_stop");
        }
    }
    completeSessionCleanup(sessionId);
    res.json({ success: true, message: "Session stopped. Backup (if linked) will continue." });
});

app.post("/stop-task", requireAuth, (req, res) => {
    const { sessionId, taskId } = req.body;
    const user = req.user;
    if (!activeClients.has(sessionId)) return res.json({ success: false, error: "Invalid Session ID" });
    const clientInfo = activeClients.get(sessionId);
    if (clientInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });
    const taskInfo = clientInfo.tasks.find(t => t.taskId === taskId);
    if (!taskInfo) return res.json({ success: false, error: "Task not found" });
    completeTaskCleanup(sessionId, taskId);
    res.json({ success: true, message: "Task stopped" });
});

// ===================================================
// GROUPS
// ===================================================
app.get("/get-groups", requireAuth, async (req, res) => {
    const user = req.user;
    const { sessionId } = req.query;
    if (!sessionId || !activeClients.has(sessionId)) return res.json({ success: false, error: "Invalid session" });
    const clientInfo = activeClients.get(sessionId);
    if (clientInfo.userId !== user.userId) return res.json({ success: false, error: "Access denied" });
    try {
        const groups = await clientInfo.client.groupFetchAllParticipating();
        const groupsList = Object.keys(groups).map((groupId, index) => {
            const group = groups[groupId];
            return {
                index: index + 1,
                groupId: groupId.replace('@g.us', ''),
                subject: group.subject || 'Unnamed Group',
                participantsCount: (group.participants || []).length,
                creation: group.creation ? formatDate(group.creation * 1000) : null
            };
        });
        res.json({ success: true, number: clientInfo.number, groups: groupsList });
    } catch (error) {
        res.json({ success: false, error: error.message });
    }
});

// ===================================================
// ERROR HANDLING
// ===================================================
process.on('uncaughtException', (error) => {
    logError('UNCAUGHT: ' + error.message);
    savePersistentData();
});
process.on('unhandledRejection', (reason, promise) => {
    logError('UNHANDLED: ' + reason);
    savePersistentData();
});
process.on('SIGINT', () => {
    logWarning('Shutting down...');
    activeClients.forEach((ci, sid) => { if (ci.client) { try { ci.client.end(); } catch(e){} } });
    savePersistentData();
    setTimeout(() => process.exit(), 5000);
});

// ===================================================
// STARTUP RECOVERY
// ===================================================
setTimeout(() => {
    logInfo('Recovering sessions...');
    activeClients.forEach((clientInfo, sessionId) => {
        if (!clientInfo.isConnected && !manuallyDisconnectedSessions.has(sessionId)) {
            recoverSession(sessionId, clientInfo);
        }
    });
    setTimeout(checkFailoverStatus, 20000);
}, 5000);

// ===================================================
// SERVER START
// ===================================================
app.listen(PORT, () => {
    logSuccess(`🚀 Server: http://localhost:${PORT}`);
    logInfo(`Admin Username: ${ADMIN_CREDENTIALS.username}`);
    logInfo(`Admin Password: ${ADMIN_CREDENTIALS.password}`);
    logSuccess('✅ INFINITE RECONNECT enabled');
    logSuccess('✅ IMAGE SENDING enabled');
    logSuccess('✅ AUTO MENTION enabled');
    logSuccess('✅ APPROVAL KEY SYSTEM enabled');
    logSuccess('🔥🔥🔥 REMOTE BACKUP / AUTO FAILOVER ENABLED 🔥🔥🔥');

    const approvals = loadApprovals();
    const pendingCount = Object.values(approvals).filter(a => a.status === 'pending').length;
    if (pendingCount > 0) {
        logWarning(`🔑 ${pendingCount} approval key(s) pending. Admin panel se approve karo.`);
    }
});