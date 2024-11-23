-- Create providers table
CREATE TABLE providers (
    id VARCHAR(255) PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    npi VARCHAR(50),
    tax_id VARCHAR(50),
    api_key TEXT,
    status VARCHAR(20) DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_verified TIMESTAMP WITH TIME ZONE,
    verified_by VARCHAR(255)
);

-- Add index for faster lookups
CREATE INDEX idx_providers_status ON providers(status);
CREATE INDEX idx_providers_npi ON providers(npi);
