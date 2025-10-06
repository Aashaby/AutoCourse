// 加密存储密钥
const STORAGE_KEY = 'course_accounts_encrypted';
const ENCRYPTED_FILE_URL = './accounts.encrypted.json'; // 加密账号文件路径

// 全局变量
let accounts = [];
let verifyCode = '';
let isGrabbing = false;
let grabbingTasks = [];
let userEncryptionKey = ''; // 用户输入的解密密钥

// 简单的加密/解密函数 (使用Base64和简单的XOR) - 用于本地存储
function encryptData(data) {
    const jsonStr = JSON.stringify(data);
    const key = 'LocalStorage_Key_2025'; // 本地存储密钥
    
    // 使用 TextEncoder 支持 UTF-8
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(jsonStr);
    const keyBytes = encoder.encode(key);
    
    // XOR 加密
    const encrypted = new Uint8Array(dataBytes.length);
    for (let i = 0; i < dataBytes.length; i++) {
        encrypted[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
    }
    
    // 转换为 Base64（支持二进制数据）
    return btoa(String.fromCharCode(...encrypted));
}

function decryptData(encrypted) {
    try {
        const key = 'LocalStorage_Key_2025'; // 本地存储密钥
        
        // 从 Base64 解码
        const encryptedBytes = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
        const encoder = new TextEncoder();
        const keyBytes = encoder.encode(key);
        
        // XOR 解密
        const decrypted = new Uint8Array(encryptedBytes.length);
        for (let i = 0; i < encryptedBytes.length; i++) {
            decrypted[i] = encryptedBytes[i] ^ keyBytes[i % keyBytes.length];
        }
        
        // 使用 TextDecoder 支持 UTF-8
        const decoder = new TextDecoder();
        const jsonStr = decoder.decode(decrypted);
        return JSON.parse(jsonStr);
    } catch (e) {
        console.error('解密本地存储失败:', e);
        return [];
    }
}

// 保存账号到本地存储
function saveAccounts() {
    const encrypted = encryptData(accounts);
    localStorage.setItem(STORAGE_KEY, encrypted);
    log('账号数据已加密保存', 'success');
}

// AES-256-CBC 解密函数（浏览器版本）
async function decryptAES(encryptedData, secretKey) {
    try {
        const parts = encryptedData.split(':');
        if (parts.length !== 2) {
            throw new Error('加密数据格式错误');
        }
        
        const iv = hexToBytes(parts[0]);
        const encrypted = hexToBytes(parts[1]);
        
        // 使用 SHA-256 生成密钥（与 Node.js 端一致）
        const keyBuffer = await crypto.subtle.digest(
            'SHA-256',
            new TextEncoder().encode(secretKey)
        );
        
        // 导入密钥
        const key = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'AES-CBC', length: 256 },
            false,
            ['decrypt']
        );
        
        // 解密
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            key,
            encrypted
        );
        
        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('解密失败:', error);
        return null;
    }
}

// 辅助函数：十六进制转字节数组
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// 从加密文件加载账号（需要用户提供密钥）
async function loadAccountsFromFile(encryptionKey) {
    try {
        log('正在从加密文件加载账号...', 'info');
        const response = await fetch(ENCRYPTED_FILE_URL);
        
        if (!response.ok) {
            throw new Error('加密文件不存在');
        }
        
        const encryptedData = await response.json();
        const decrypted = await decryptAES(encryptedData.encrypted, encryptionKey);
        
        if (decrypted) {
            accounts = JSON.parse(decrypted);
            renderAccounts();
            log(`✅ 成功加载 ${accounts.length} 个账号（来自加密文件）`, 'success');
            return true;
        } else {
            log('❌ 解密失败，请检查密钥是否正确', 'error');
            return false;
        }
    } catch (error) {
        log(`加载加密文件失败: ${error.message}`, 'warning');
        return false;
    }
}

// 解密并加载账号（从UI调用）
async function decryptAndLoadAccounts() {
    const key = document.getElementById('decryptionKey').value.trim();
    
    if (!key) {
        log('请输入解密密钥', 'error');
        return;
    }
    
    userEncryptionKey = key;
    const success = await loadAccountsFromFile(key);
    
    if (success) {
        // 隐藏密钥输入区域，显示主界面
        document.getElementById('keyInputSection').classList.add('hidden');
        document.getElementById('mainCard').classList.remove('hidden');
        document.getElementById('logSection').classList.remove('hidden');
        log('账号数据已成功解密并加载', 'success');
    } else {
        log('解密失败，请检查密钥是否正确', 'error');
    }
}

// 跳过解密，直接进入主界面
function skipDecryption() {
    log('已跳过解密，可以手动添加账号', 'info');
    document.getElementById('keyInputSection').classList.add('hidden');
    document.getElementById('mainCard').classList.remove('hidden');
    document.getElementById('logSection').classList.remove('hidden');
    
    // 尝试从本地存储加载
    loadAccounts();
}

// 从本地存储加载账号
function loadAccounts() {
    const encrypted = localStorage.getItem(STORAGE_KEY);
    if (encrypted) {
        accounts = decryptData(encrypted);
        renderAccounts();
        log(`已加载 ${accounts.length} 个账号（来自本地存储）`, 'info');
    }
}

// 添加账号
function addAccount() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const courseTaskId = document.getElementById('courseTaskId').value.trim();
    const nickname = document.getElementById('nickname').value.trim() || '未命名';

    if (!username || !password || !courseTaskId) {
        log('请填写完整的账号、密码和课程任务ID', 'error');
        return;
    }

    accounts.push({ username, password, courseTaskId, nickname });
    saveAccounts();
    renderAccounts();

    // 清空输入框
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    document.getElementById('courseTaskId').value = '';
    document.getElementById('nickname').value = '';

    log(`已添加账号: ${nickname} (${username})`, 'success');
}

// 删除账号
function deleteAccount(index) {
    const account = accounts[index];
    if (confirm(`确定删除账号 ${account.nickname} (${account.username}) 吗？`)) {
        accounts.splice(index, 1);
        saveAccounts();
        renderAccounts();
        log(`已删除账号: ${account.nickname}`, 'info');
    }
}

// 渲染账号列表
function renderAccounts() {
    const container = document.getElementById('accountsList');
    if (accounts.length === 0) {
        container.innerHTML = '<p class="text-gray-500 text-center py-4">暂无账号，请添加账号</p>';
        return;
    }

    container.innerHTML = accounts.map((account, index) => `
        <div class="bg-indigo-50 border border-indigo-200 rounded-lg p-4 flex items-center justify-between hover:bg-indigo-100 transition">
            <div class="flex-grow">
                <div class="font-semibold text-gray-800">${account.nickname}</div>
                <div class="text-sm text-gray-600">账号: ${account.username} | 课程ID: ${account.courseTaskId}</div>
            </div>
            <button onclick="deleteAccount(${index})" 
                class="bg-red-500 hover:bg-red-600 text-white py-1 px-3 rounded transition">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `).join('');
}

// 获取验证码
async function getCaptcha() {
    try {
        log('正在获取验证码...', 'info');
        const response = await fetch('https://dgsshwlxx.lvya.org/common/eos/login/getAuthCode?schoolId=3297');
        const data = await response.json();
        
        if (data.data && data.data.img) {
            verifyCode = data.data.verify;
            const imgElement = document.getElementById('captchaImage');
            const placeholder = document.getElementById('captchaPlaceholder');
            
            imgElement.src = 'data:image/png;base64,' + data.data.img;
            imgElement.classList.remove('hidden');
            placeholder.classList.add('hidden');
            
            log('验证码获取成功', 'success');
        } else {
            log('验证码获取失败: ' + JSON.stringify(data), 'error');
        }
    } catch (error) {
        log('验证码获取失败: ' + error.message, 'error');
    }
}

// MD5加密函数（完整实现）
function md5(string) {
    function rotateLeft(value, shift) {
        return (value << shift) | (value >>> (32 - shift));
    }
    
    function addUnsigned(x, y) {
        const lsw = (x & 0xFFFF) + (y & 0xFFFF);
        const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }
    
    function md5cycle(x, k) {
        let a = x[0], b = x[1], c = x[2], d = x[3];
        
        a = ff(a, b, c, d, k[0], 7, -680876936);
        d = ff(d, a, b, c, k[1], 12, -389564586);
        c = ff(c, d, a, b, k[2], 17, 606105819);
        b = ff(b, c, d, a, k[3], 22, -1044525330);
        a = ff(a, b, c, d, k[4], 7, -176418897);
        d = ff(d, a, b, c, k[5], 12, 1200080426);
        c = ff(c, d, a, b, k[6], 17, -1473231341);
        b = ff(b, c, d, a, k[7], 22, -45705983);
        a = ff(a, b, c, d, k[8], 7, 1770035416);
        d = ff(d, a, b, c, k[9], 12, -1958414417);
        c = ff(c, d, a, b, k[10], 17, -42063);
        b = ff(b, c, d, a, k[11], 22, -1990404162);
        a = ff(a, b, c, d, k[12], 7, 1804603682);
        d = ff(d, a, b, c, k[13], 12, -40341101);
        c = ff(c, d, a, b, k[14], 17, -1502002290);
        b = ff(b, c, d, a, k[15], 22, 1236535329);
        
        a = gg(a, b, c, d, k[1], 5, -165796510);
        d = gg(d, a, b, c, k[6], 9, -1069501632);
        c = gg(c, d, a, b, k[11], 14, 643717713);
        b = gg(b, c, d, a, k[0], 20, -373897302);
        a = gg(a, b, c, d, k[5], 5, -701558691);
        d = gg(d, a, b, c, k[10], 9, 38016083);
        c = gg(c, d, a, b, k[15], 14, -660478335);
        b = gg(b, c, d, a, k[4], 20, -405537848);
        a = gg(a, b, c, d, k[9], 5, 568446438);
        d = gg(d, a, b, c, k[14], 9, -1019803690);
        c = gg(c, d, a, b, k[3], 14, -187363961);
        b = gg(b, c, d, a, k[8], 20, 1163531501);
        a = gg(a, b, c, d, k[13], 5, -1444681467);
        d = gg(d, a, b, c, k[2], 9, -51403784);
        c = gg(c, d, a, b, k[7], 14, 1735328473);
        b = gg(b, c, d, a, k[12], 20, -1926607734);
        
        a = hh(a, b, c, d, k[5], 4, -378558);
        d = hh(d, a, b, c, k[8], 11, -2022574463);
        c = hh(c, d, a, b, k[11], 16, 1839030562);
        b = hh(b, c, d, a, k[14], 23, -35309556);
        a = hh(a, b, c, d, k[1], 4, -1530992060);
        d = hh(d, a, b, c, k[4], 11, 1272893353);
        c = hh(c, d, a, b, k[7], 16, -155497632);
        b = hh(b, c, d, a, k[10], 23, -1094730640);
        a = hh(a, b, c, d, k[13], 4, 681279174);
        d = hh(d, a, b, c, k[0], 11, -358537222);
        c = hh(c, d, a, b, k[3], 16, -722521979);
        b = hh(b, c, d, a, k[6], 23, 76029189);
        a = hh(a, b, c, d, k[9], 4, -640364487);
        d = hh(d, a, b, c, k[12], 11, -421815835);
        c = hh(c, d, a, b, k[15], 16, 530742520);
        b = hh(b, c, d, a, k[2], 23, -995338651);
        
        a = ii(a, b, c, d, k[0], 6, -198630844);
        d = ii(d, a, b, c, k[7], 10, 1126891415);
        c = ii(c, d, a, b, k[14], 15, -1416354905);
        b = ii(b, c, d, a, k[5], 21, -57434055);
        a = ii(a, b, c, d, k[12], 6, 1700485571);
        d = ii(d, a, b, c, k[3], 10, -1894986606);
        c = ii(c, d, a, b, k[10], 15, -1051523);
        b = ii(b, c, d, a, k[1], 21, -2054922799);
        a = ii(a, b, c, d, k[8], 6, 1873313359);
        d = ii(d, a, b, c, k[15], 10, -30611744);
        c = ii(c, d, a, b, k[6], 15, -1560198380);
        b = ii(b, c, d, a, k[13], 21, 1309151649);
        a = ii(a, b, c, d, k[4], 6, -145523070);
        d = ii(d, a, b, c, k[11], 10, -1120210379);
        c = ii(c, d, a, b, k[2], 15, 718787259);
        b = ii(b, c, d, a, k[9], 21, -343485551);
        
        x[0] = addUnsigned(a, x[0]);
        x[1] = addUnsigned(b, x[1]);
        x[2] = addUnsigned(c, x[2]);
        x[3] = addUnsigned(d, x[3]);
    }
    
    function cmn(q, a, b, x, s, t) {
        a = addUnsigned(addUnsigned(a, q), addUnsigned(x, t));
        return addUnsigned(rotateLeft(a, s), b);
    }
    
    function ff(a, b, c, d, x, s, t) {
        return cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }
    
    function gg(a, b, c, d, x, s, t) {
        return cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }
    
    function hh(a, b, c, d, x, s, t) {
        return cmn(b ^ c ^ d, a, b, x, s, t);
    }
    
    function ii(a, b, c, d, x, s, t) {
        return cmn(c ^ (b | (~d)), a, b, x, s, t);
    }
    
    function md51(s) {
        const n = s.length;
        const state = [1732584193, -271733879, -1732584194, 271733878];
        let i;
        for (i = 64; i <= s.length; i += 64) {
            md5cycle(state, md5blk(s.substring(i - 64, i)));
        }
        s = s.substring(i - 64);
        const tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < s.length; i++)
            tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3);
        if (i > 55) {
            md5cycle(state, tail);
            for (i = 0; i < 16; i++) tail[i] = 0;
        }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return state;
    }
    
    function md5blk(s) {
        const md5blks = [];
        for (let i = 0; i < 64; i += 4) {
            md5blks[i >> 2] = s.charCodeAt(i) +
                (s.charCodeAt(i + 1) << 8) +
                (s.charCodeAt(i + 2) << 16) +
                (s.charCodeAt(i + 3) << 24);
        }
        return md5blks;
    }
    
    function rhex(n) {
        let s = '', j = 0;
        for (; j < 4; j++)
            s += '0123456789abcdef'.charAt((n >> (j * 8 + 4)) & 0x0F) +
                '0123456789abcdef'.charAt((n >> (j * 8)) & 0x0F);
        return s;
    }
    
    function hex(x) {
        for (let i = 0; i < x.length; i++)
            x[i] = rhex(x[i]);
        return x.join('');
    }
    
    return hex(md51(string));
}

// 登录并获取token
async function login(username, password, code) {
    try {
        // MD5加密密码
        const encryptedPassword = md5(password);
        
        const loginPayload = new URLSearchParams({
            name: username,
            pwd: encryptedPassword,
            type: '1',
            code: code,
            verifyCode: verifyCode
        });

        const loginResponse = await fetch('https://yun.lvya.org/auth/eos/login/pwd?schoolId=3297', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: loginPayload
        });

        const loginData = await loginResponse.json();
        const authorizationCode = loginData.data;

        if (!authorizationCode) {
            log(`登录失败 ${username}: ${loginData.errorDesc || '未知错误'}`, 'error');
            return null;
        }

        const tokenPayload = new URLSearchParams({
            authorizationCode: authorizationCode
        });

        const tokenResponse = await fetch('https://dgsshwlxx.lvya.org/auth/eos/login/getToken?schoolId=3297', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: tokenPayload
        });

        const tokenData = await tokenResponse.json();
        const token = tokenData.data?.token;
        const nickname = tokenData.data?.user?.nickname || '未知姓名';

        if (!token) {
            log(`获取Token失败: ${username}`, 'error');
            return null;
        }

        log(`登录成功: ${nickname}`, 'success');
        return { token, nickname };
    } catch (error) {
        log(`登录异常 ${username}: ${error.message}`, 'error');
        return null;
    }
}

// 抢课任务（高速模式，无延迟）
async function grabCourse(account, code, token) {
    const headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Bearer ${token}`
    };

    const payload = new URLSearchParams({
        courseTaskId: account.courseTaskId
    });

    // 高速循环，与Python版本一致
    while (isGrabbing) {
        try {
            const response = await fetch('https://dgsshwlxx.lvya.org/develop/course/task/stu/signTask?schoolId=3297&appSourceType=1', {
                method: 'POST',
                headers: headers,
                body: payload
            });

            const data = await response.json();
            log(`${account.nickname}: ${JSON.stringify(data)}`, 'info');

            if (data.isSuccess === true) {
                log(`✅ 抢课成功! 账号: ${account.username}, 姓名: ${account.nickname}, 课程: ${account.courseTaskId}`, 'success');
                return true;
            }

            // 无延迟，立即重试（与Python版本一致）
        } catch (error) {
            log(`抢课请求失败 ${account.nickname}: ${error.message}`, 'error');
            // 错误时稍微延迟，避免过度请求
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }
    return false;
}

// 开始抢课
async function startGrabbing() {
    if (accounts.length === 0) {
        log('请先添加账号', 'error');
        return;
    }

    const code = document.getElementById('captchaInput').value.trim();
    if (!code) {
        log('请输入验证码', 'error');
        return;
    }

    if (!verifyCode) {
        log('请先获取验证码', 'error');
        return;
    }

    isGrabbing = true;
    log('========== 开始抢课 ==========', 'info');

    // 为每个账号创建抢课任务
    grabbingTasks = accounts.map(async (account) => {
        const loginResult = await login(account.username, account.password, code);
        if (loginResult) {
            await grabCourse(account, code, loginResult.token);
        }
    });

    await Promise.all(grabbingTasks);
    log('========== 抢课结束 ==========', 'info');
}

// 停止抢课
function stopGrabbing() {
    isGrabbing = false;
    log('已停止抢课', 'info');
}

// 日志输出
function log(message, type = 'info') {
    const container = document.getElementById('logContainer');
    const timestamp = new Date().toLocaleTimeString('zh-CN');
    
    let colorClass = 'text-green-400';
    let icon = 'ℹ️';
    
    if (type === 'error') {
        colorClass = 'text-red-400';
        icon = '❌';
    } else if (type === 'success') {
        colorClass = 'text-green-300';
        icon = '✅';
    } else if (type === 'warning') {
        colorClass = 'text-yellow-400';
        icon = '⚠️';
    }

    const logEntry = document.createElement('div');
    logEntry.className = colorClass;
    logEntry.innerHTML = `[${timestamp}] ${icon} ${message}`;
    
    // 如果是第一条日志，清空占位符
    if (container.querySelector('.text-gray-500')) {
        container.innerHTML = '';
    }
    
    container.appendChild(logEntry);
    container.scrollTop = container.scrollHeight;
}

// 清空日志
function clearLog() {
    document.getElementById('logContainer').innerHTML = '<div class="text-gray-500">等待操作...</div>';
}

// 显示/隐藏密钥输入
function showKeyInput() {
    document.getElementById('keyInputSection').classList.remove('hidden');
    document.getElementById('mainCard').classList.add('hidden');
    document.getElementById('logSection').classList.add('hidden');
}

// 页面加载时初始化
window.addEventListener('DOMContentLoaded', () => {
    log('系统已就绪，请输入解密密钥或跳过', 'info');
    log('⚠️ 注意: 由于浏览器安全限制，某些API可能需要CORS支持', 'warning');
    
    // 为密钥输入框添加回车事件
    document.getElementById('decryptionKey').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            decryptAndLoadAccounts();
        }
    });
});
