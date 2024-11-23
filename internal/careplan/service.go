package careplan

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mesikahq/hipaa-exchange/internal/audit"
)

type CarePlan struct {
	ID             string    `json:"id"`
	PatientID      string    `json:"patient_id"`
	ProviderID     string    `json:"provider_id"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Goals          []string  `json:"goals"`
	Interventions  []string  `json:"interventions"`
	Status         string    `json:"status"`
	StartDate      time.Time `json:"start_date"`
	EndDate        time.Time `json:"end_date"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedBy      string    `json:"created_by"`
	LastModifiedBy string    `json:"last_modified_by"`
}

type Service interface {
	Create(ctx context.Context, carePlan *CarePlan) error
	Get(ctx context.Context, id string) (*CarePlan, error)
	List(ctx context.Context, patientID string) ([]*CarePlan, error)
	ListAll(ctx context.Context) ([]*CarePlan, error)
	Update(ctx context.Context, carePlan *CarePlan) error
	Delete(ctx context.Context, id string) error
}

type service struct {
	db    *pgxpool.Pool
	audit audit.Service
}

func NewService(db *pgxpool.Pool, audit audit.Service) Service {
	return &service{
		db:    db,
		audit: audit,
	}
}

func (s *service) Create(ctx context.Context, carePlan *CarePlan) error {
	now := time.Now()
	userID := ctx.Value("user_id").(string)

	carePlan.CreatedAt = now
	carePlan.UpdatedAt = now
	carePlan.CreatedBy = userID
	carePlan.LastModifiedBy = userID

	_, err := s.db.Exec(ctx, `
		INSERT INTO care_plans (
			id, patient_id, provider_id, title, description, 
			goals, interventions, status, start_date, end_date, 
			created_at, updated_at, created_by, last_modified_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 
			$11, $12, $13, $14
		)
	`,
		carePlan.ID, carePlan.PatientID, carePlan.ProviderID, carePlan.Title, carePlan.Description,
		carePlan.Goals, carePlan.Interventions, carePlan.Status, carePlan.StartDate, carePlan.EndDate,
		carePlan.CreatedAt, carePlan.UpdatedAt, carePlan.CreatedBy, carePlan.LastModifiedBy,
	)

	if err != nil {
		return err
	}

	// Log audit event
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "CREATE",
		Resource:    "care_plan",
		ResourceID:  carePlan.ID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return nil
}

func (s *service) Get(ctx context.Context, id string) (*CarePlan, error) {
	var carePlan CarePlan
	err := s.db.QueryRow(ctx, `
		SELECT 
			id, patient_id, provider_id, title, description, 
			goals, interventions, status, start_date, end_date, 
			created_at, updated_at, created_by, last_modified_by 
		FROM care_plans 
		WHERE id = $1
	`, id).Scan(
		&carePlan.ID, &carePlan.PatientID, &carePlan.ProviderID, &carePlan.Title, &carePlan.Description,
		&carePlan.Goals, &carePlan.Interventions, &carePlan.Status, &carePlan.StartDate, &carePlan.EndDate,
		&carePlan.CreatedAt, &carePlan.UpdatedAt, &carePlan.CreatedBy, &carePlan.LastModifiedBy,
	)

	if err != nil {
		return nil, err
	}

	// Log audit event
	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "READ",
		Resource:    "care_plan",
		ResourceID:  carePlan.ID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return &carePlan, nil
}

func (s *service) List(ctx context.Context, patientID string) ([]*CarePlan, error) {
	rows, err := s.db.Query(ctx, `
		SELECT 
			id, patient_id, provider_id, title, description, 
			goals, interventions, status, start_date, end_date, 
			created_at, updated_at, created_by, last_modified_by 
		FROM care_plans 
		WHERE patient_id = $1
	`, patientID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var carePlans []*CarePlan
	for rows.Next() {
		var carePlan CarePlan
		err := rows.Scan(
			&carePlan.ID, &carePlan.PatientID, &carePlan.ProviderID, &carePlan.Title, &carePlan.Description,
			&carePlan.Goals, &carePlan.Interventions, &carePlan.Status, &carePlan.StartDate, &carePlan.EndDate,
			&carePlan.CreatedAt, &carePlan.UpdatedAt, &carePlan.CreatedBy, &carePlan.LastModifiedBy,
		)

		if err != nil {
			return nil, err
		}
		carePlans = append(carePlans, &carePlan)
	}

	// Log audit event
	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "LIST",
		Resource:    "care_plan",
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return carePlans, nil
}

func (s *service) ListAll(ctx context.Context) ([]*CarePlan, error) {
	rows, err := s.db.Query(ctx, `
		SELECT 
			id, patient_id, provider_id, title, description, 
			goals, interventions, status, start_date, end_date, 
			created_at, updated_at, created_by, last_modified_by 
		FROM care_plans
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var carePlans []*CarePlan
	for rows.Next() {
		var carePlan CarePlan
		err := rows.Scan(
			&carePlan.ID, &carePlan.PatientID, &carePlan.ProviderID, &carePlan.Title, &carePlan.Description,
			&carePlan.Goals, &carePlan.Interventions, &carePlan.Status, &carePlan.StartDate, &carePlan.EndDate,
			&carePlan.CreatedAt, &carePlan.UpdatedAt, &carePlan.CreatedBy, &carePlan.LastModifiedBy,
		)

		if err != nil {
			return nil, err
		}
		carePlans = append(carePlans, &carePlan)
	}

	// Log audit event
	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventAccess,
		UserID:      userID,
		Action:      "LIST_ALL",
		Resource:    "care_plan",
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return carePlans, nil
}

func (s *service) Update(ctx context.Context, carePlan *CarePlan) error {
	now := time.Now()
	userID := ctx.Value("user_id").(string)

	carePlan.UpdatedAt = now
	carePlan.LastModifiedBy = userID

	_, err := s.db.Exec(ctx, `
		UPDATE care_plans SET
			title = $1, description = $2, 
			goals = $3, interventions = $4, status = $5, 
			start_date = $6, end_date = $7, 
			updated_at = $8, last_modified_by = $9
		WHERE id = $10
	`,
		carePlan.Title, carePlan.Description, carePlan.Goals, carePlan.Interventions,
		carePlan.Status, carePlan.StartDate, carePlan.EndDate,
		carePlan.UpdatedAt, carePlan.LastModifiedBy, carePlan.ID,
	)

	if err != nil {
		return err
	}

	// Log audit event
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "UPDATE",
		Resource:    "care_plan",
		ResourceID:  carePlan.ID,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return nil
}

func (s *service) Delete(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `
		DELETE FROM care_plans 
		WHERE id = $1
	`, id)

	if err != nil {
		return err
	}

	// Log audit event
	userID := ctx.Value("user_id").(string)
	s.audit.LogEvent(ctx, &audit.AuditEvent{
		EventType:   audit.EventModify,
		UserID:      userID,
		Action:      "DELETE",
		Resource:    "care_plan",
		ResourceID:  id,
		Status:      "success",
		Sensitivity: "HIGH",
	})

	return nil
}
