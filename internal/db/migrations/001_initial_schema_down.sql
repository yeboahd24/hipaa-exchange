-- Drop triggers first
DROP TRIGGER IF EXISTS update_patient_contacts_updated_at ON patient_contacts;
DROP TRIGGER IF EXISTS update_patient_addresses_updated_at ON patient_addresses;
DROP TRIGGER IF EXISTS update_patients_updated_at ON patients;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_patients_names;
DROP INDEX IF EXISTS idx_patient_identifiers_type;
DROP INDEX IF EXISTS idx_patient_contacts_type;
DROP INDEX IF EXISTS idx_patient_insurance_provider;

-- Drop tables in reverse order of dependencies
DROP TABLE IF EXISTS restricted_providers;
DROP TABLE IF EXISTS patient_insurance;
DROP TABLE IF EXISTS patient_contacts;
DROP TABLE IF EXISTS patient_addresses;
DROP TABLE IF EXISTS patient_identifiers;
DROP TABLE IF EXISTS patients;
