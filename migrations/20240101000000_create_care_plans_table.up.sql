-- Create care_plans table
CREATE TABLE care_plans (
    id UUID PRIMARY KEY,
    patient_id UUID NOT NULL REFERENCES patients(id),
    provider_id UUID NOT NULL REFERENCES providers(id),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    goals TEXT[],
    interventions TEXT[],
    status VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
    start_date TIMESTAMP WITH TIME ZONE,
    end_date TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    last_modified_by UUID NOT NULL REFERENCES users(id)
);

-- Create index for faster patient-based queries
CREATE INDEX idx_care_plans_patient_id ON care_plans(patient_id);
