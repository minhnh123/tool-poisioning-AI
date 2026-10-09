-- Enterprise MCP Gateway Schema
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) UNIQUE NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'viewer',
    api_key_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_policies (
    id SERIAL PRIMARY KEY,
    policy_name VARCHAR(64) NOT NULL,
    threat_category VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
