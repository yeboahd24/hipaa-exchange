CREATE TYPE consent_type AS ENUM ('DATA_SHARING', 'RESEARCH', 'EMERGENCY_ACCESS');
CREATE TYPE consent_status AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED', 'PENDING');

CREATE TABLE IF NOT EXISTS consents (
    id UUID PRIMARY KEY,
    patient_id UUID NOT NULL REFERENCES patients(id),
    type consent_type NOT NULL,
    status consent_status NOT NULL DEFAULT 'PENDING',
    granted_to UUID[] NOT NULL,
    purpose TEXT NOT NULL,
    start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    end_date TIMESTAMP WITH TIME ZONE NOT NULL,
    restrictions UUID[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID NOT NULL REFERENCES users(id),
    last_modified_by UUID NOT NULL REFERENCES users(id),
    signed_by UUID REFERENCES users(id),
    signature_date TIMESTAMP WITH TIME ZONE,
    CONSTRAINT consents_dates_check CHECK (start_date <= end_date)
);

CREATE INDEX idx_consents_patient_id ON consents(patient_id);
CREATE INDEX idx_consents_status ON consents(status);
CREATE INDEX idx_consents_type ON consents(type);
CREATE INDEX idx_consents_granted_to ON consents USING GIN(granted_to);
