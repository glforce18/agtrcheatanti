-- ============================================
-- AGTR v15.0 - Dynamic Blacklist System
-- ============================================
-- Server-side blacklist storage for dynamic updates
-- DLL will fetch these at runtime instead of hardcoded lists

-- 1. Process Blacklist
CREATE TABLE IF NOT EXISTS agtr_blacklist_processes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    process_name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    category VARCHAR(100),  -- debugger, cheat, macro, overlay, etc.
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_enabled (enabled),
    INDEX idx_severity (severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. DLL Blacklist
CREATE TABLE IF NOT EXISTS agtr_blacklist_dlls (
    id INT AUTO_INCREMENT PRIMARY KEY,
    dll_name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    category VARCHAR(100),  -- hook, inject, cheat, etc.
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 3. File Hash Blacklist (MD5/SHA256)
CREATE TABLE IF NOT EXISTS agtr_blacklist_hashes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hash_value VARCHAR(64) NOT NULL UNIQUE,  -- MD5 (32 chars) or SHA256 (64 chars)
    hash_type ENUM('md5', 'sha256') NOT NULL,
    file_name VARCHAR(255),  -- Optional, for reference
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'high',
    source VARCHAR(100),  -- virustotal, community, manual, etc.
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_hash (hash_value),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 4. Memory String Patterns
CREATE TABLE IF NOT EXISTS agtr_blacklist_strings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pattern VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    regex BOOLEAN DEFAULT FALSE,  -- Is this a regex pattern?
    case_sensitive BOOLEAN DEFAULT FALSE,
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 5. Window Title Blacklist
CREATE TABLE IF NOT EXISTS agtr_blacklist_windows (
    id INT AUTO_INCREMENT PRIMARY KEY,
    window_pattern VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 6. Registry Key Blacklist
CREATE TABLE IF NOT EXISTS agtr_blacklist_registry (
    id INT AUTO_INCREMENT PRIMARY KEY,
    registry_path VARCHAR(500) NOT NULL UNIQUE,
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 7. Driver Blacklist
CREATE TABLE IF NOT EXISTS agtr_blacklist_drivers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    driver_name VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(500),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'high',
    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    added_by VARCHAR(100) DEFAULT 'system',
    enabled BOOLEAN DEFAULT TRUE,
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 8. Blacklist Update Log (for versioning)
CREATE TABLE IF NOT EXISTS agtr_blacklist_updates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    blacklist_type ENUM('processes', 'dlls', 'hashes', 'strings', 'windows', 'registry', 'drivers'),
    version INT NOT NULL,
    update_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    changes_count INT DEFAULT 0,
    updated_by VARCHAR(100) DEFAULT 'system',
    INDEX idx_type (blacklist_type),
    INDEX idx_version (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- INSERT DEFAULT BLACKLIST DATA
-- ============================================

-- Default Process Blacklist
INSERT INTO agtr_blacklist_processes (process_name, description, severity, category) VALUES
('cheatengine', 'Cheat Engine - Memory editor', 'critical', 'cheat'),
('cheatengine-x86_64', 'Cheat Engine 64-bit', 'critical', 'cheat'),
('cheatengine-x86', 'Cheat Engine 32-bit', 'critical', 'cheat'),
('artmoney', 'ArtMoney - Memory editor', 'critical', 'cheat'),
('ollydbg', 'OllyDbg - Debugger', 'high', 'debugger'),
('x64dbg', 'x64dbg - Debugger', 'high', 'debugger'),
('x32dbg', 'x32dbg - Debugger', 'high', 'debugger'),
('processhacker', 'Process Hacker - Process tool', 'medium', 'debugger'),
('ida.exe', 'IDA Pro - Disassembler', 'high', 'debugger'),
('ida64.exe', 'IDA Pro 64-bit', 'high', 'debugger'),
('wireshark', 'Wireshark - Network analyzer', 'low', 'network'),
('fiddler', 'Fiddler - HTTP debugger', 'low', 'network'),
('autohotkey', 'AutoHotkey - Macro tool', 'medium', 'macro'),
('autoit3', 'AutoIt - Automation', 'medium', 'macro'),
('reshade', 'ReShade - Graphics injector', 'low', 'overlay'),
('sweetfx', 'SweetFX - Graphics mod', 'low', 'overlay')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Default DLL Blacklist
INSERT INTO agtr_blacklist_dlls (dll_name, description, severity, category) VALUES
('hook.dll', 'Generic hook DLL', 'high', 'hook'),
('inject.dll', 'Generic injection DLL', 'high', 'inject'),
('cheat.dll', 'Generic cheat DLL', 'critical', 'cheat'),
('hack.dll', 'Generic hack DLL', 'critical', 'cheat'),
('aimbot.dll', 'Aimbot DLL', 'critical', 'cheat'),
('trainer.dll', 'Game trainer DLL', 'high', 'cheat'),
('minhook', 'MinHook library', 'medium', 'hook'),
('detours.dll', 'Microsoft Detours', 'medium', 'hook'),
('easyhook', 'EasyHook library', 'medium', 'hook'),
('d3d9_wrapper.dll', 'D3D9 wrapper (suspicious)', 'medium', 'overlay'),
('opengl32_wrapper.dll', 'OpenGL wrapper (suspicious)', 'medium', 'overlay')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Default String Patterns
INSERT INTO agtr_blacklist_strings (pattern, description, severity, case_sensitive) VALUES
('aimbot', 'Aimbot reference', 'critical', FALSE),
('aim_bot', 'Aimbot reference (underscore)', 'critical', FALSE),
('wallhack', 'Wallhack reference', 'critical', FALSE),
('esp_draw', 'ESP drawing function', 'critical', FALSE),
('esp_box', 'ESP box drawing', 'critical', FALSE),
('triggerbot', 'Triggerbot reference', 'critical', FALSE),
('norecoil', 'No recoil hack', 'critical', FALSE),
('no_recoil', 'No recoil hack (underscore)', 'critical', FALSE),
('bhop', 'Bunny hop script', 'high', FALSE),
('speedhack', 'Speed hack', 'critical', FALSE),
('godmode', 'God mode cheat', 'critical', FALSE),
('cheat_enable', 'Cheat enable flag', 'critical', FALSE),
('imgui::begin', 'ImGui menu (cheat UI)', 'high', FALSE),
('d3d9_hook', 'D3D9 hook', 'high', FALSE),
('opengl_hook', 'OpenGL hook', 'high', FALSE),
('present_hook', 'Present hook (overlay)', 'medium', FALSE)
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Default Window Patterns
INSERT INTO agtr_blacklist_windows (window_pattern, description, severity) VALUES
('cheat engine', 'Cheat Engine window', 'critical'),
('artmoney', 'ArtMoney window', 'critical'),
('[aimbot]', 'Aimbot menu', 'critical'),
('[wallhack]', 'Wallhack menu', 'critical'),
('[esp]', 'ESP menu', 'critical'),
('trainer', 'Game trainer', 'high'),
('injector', 'DLL injector', 'high'),
('speed hack', 'Speed hack tool', 'critical'),
('game hack', 'Generic game hack', 'critical')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Default Registry Blacklist
INSERT INTO agtr_blacklist_registry (registry_path, description, severity) VALUES
('SOFTWARE\\Cheat Engine', 'Cheat Engine registry', 'critical'),
('SOFTWARE\\ArtMoney', 'ArtMoney registry', 'critical'),
('SOFTWARE\\AutoHotkey', 'AutoHotkey registry', 'medium')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Default Driver Blacklist
INSERT INTO agtr_blacklist_drivers (driver_name, description, severity) VALUES
('kdmapper', 'Kernel driver mapper', 'critical'),
('drvmap', 'Driver mapper', 'critical'),
('capcom', 'Capcom driver exploit', 'critical'),
('gdrv', 'Gigabyte driver exploit', 'critical'),
('cpuz', 'CPU-Z driver (vulnerable)', 'high'),
('AsIO', 'ASRock driver (vulnerable)', 'high'),
('WinRing0', 'WinRing0 driver (vulnerable)', 'high')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- Initialize version tracking
INSERT INTO agtr_blacklist_updates (blacklist_type, version, changes_count) VALUES
('processes', 1, 16),
('dlls', 1, 11),
('strings', 1, 16),
('windows', 1, 9),
('registry', 1, 3),
('drivers', 1, 7);
