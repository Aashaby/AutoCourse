// 账号数据加密工具
// 运行此脚本生成加密的账号数据文件

const fs = require('fs');
const crypto = require('crypto');

// 加密配置
const ENCRYPTION_KEY = '@'; 
const ALGORITHM = 'aes-256-cbc';

// 从 accounts.csv 读取数据
function readAccountsCSV() {
    try {
        const content = fs.readFileSync('accounts.csv', 'utf-8');
        const lines = content.trim().split('\n');
        const accounts = [];
        
        // 跳过标题行
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line) continue;
            
            const parts = line.split(',');
            if (parts.length >= 3) {
                accounts.push({
                    username: parts[0].trim(),
                    password: parts[1].trim(),
                    courseTaskId: parts[2].trim(),
                    nickname: parts[3] ? parts[3].trim() : '未命名'
                });
            }
        }
        
        return accounts;
    } catch (error) {
        console.error('读取 accounts.csv 失败:', error.message);
        return [];
    }
}

// AES-256-CBC 加密
function encrypt(text, secretKey) {
    // 生成密钥和IV
    const key = crypto.createHash('sha256').update(secretKey).digest();
    const iv = crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // 返回 IV + 加密数据
    return iv.toString('hex') + ':' + encrypted;
}

// 生成加密的账号数据
function generateEncryptedData() {
    const accounts = readAccountsCSV();
    
    if (accounts.length === 0) {
        console.log('❌ 没有找到账号数据');
        return;
    }
    
    console.log(`📋 读取到 ${accounts.length} 个账号`);
    
    // 转换为 JSON
    const jsonData = JSON.stringify(accounts);
    
    // 加密数据
    const encrypted = encrypt(jsonData, ENCRYPTION_KEY);
    
    // 保存到文件
    const output = {
        version: '1.0',
        encrypted: encrypted,
        timestamp: new Date().toISOString()
    };
    
    fs.writeFileSync('accounts.encrypted.json', JSON.stringify(output, null, 2));
    
    console.log('✅ 加密文件已生成: accounts.encrypted.json');
    console.log('📝 请将此文件上传到 GitHub，并删除 accounts.csv');
    console.log('⚠️  注意: 不要将 accounts.csv 上传到 GitHub！');
}

// 执行
generateEncryptedData();
