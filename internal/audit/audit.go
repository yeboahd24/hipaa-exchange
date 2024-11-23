package audit

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/sirupsen/logrus"
)

type EventType string

const (
	EventAccess          EventType = "ACCESS"
	EventModify          EventType = "MODIFY"
	EventDelete          EventType = "DELETE"
	EventLogin           EventType = "LOGIN"
	EventLogout          EventType = "LOGOUT"
	EventConsent         EventType = "CONSENT"
	EventTransfer        EventType = "TRANSFER"
	EventEmergencyAccess EventType = "EMERGENCY_ACCESS"
	EventTypeBreakGlass  EventType = "BREAK_GLASS"
)

type AuditEvent struct {
	Timestamp   time.Time       `json:"timestamp"`
	EventType   EventType       `json:"event_type"`
	UserID      string          `json:"user_id"`
	Action      string          `json:"action"`
	Resource    string          `json:"resource"`
	ResourceID  string          `json:"resource_id"`
	IPAddress   string          `json:"ip_address"`
	UserAgent   string          `json:"user_agent"`
	RequestID   string          `json:"request_id"`
	Status      string          `json:"status"`
	Details     json.RawMessage `json:"details,omitempty"`
	Sensitivity string          `json:"sensitivity"`
}

type Service interface {
	LogEvent(ctx context.Context, event *AuditEvent) error
	QueryEvents(ctx context.Context, filters map[string]interface{}, from, size int) ([]AuditEvent, error)
}

type service struct {
	es     *elasticsearch.Client
	logger *logrus.Logger
}

func NewService(esClient *elasticsearch.Client) Service {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	return &service{
		es:     esClient,
		logger: logger,
	}
}

func (s *service) LogEvent(ctx context.Context, event *AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Log to Elasticsearch
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	index := "hipaa_audit_" + time.Now().Format("2006.01")
	_, err = s.es.Index(
		index,
		strings.NewReader(string(payload)),
		s.es.Index.WithContext(ctx),
		s.es.Index.WithRefresh("true"),
	)
	if err != nil {
		s.logger.WithError(err).Error("Failed to index audit event")
		return err
	}

	// Also log to system logger for redundancy
	s.logger.WithFields(logrus.Fields{
		"event_type":  event.EventType,
		"user_id":     event.UserID,
		"resource":    event.Resource,
		"resource_id": event.ResourceID,
		"ip_address":  event.IPAddress,
		"request_id":  event.RequestID,
		"status":      event.Status,
		"sensitivity": event.Sensitivity,
	}).Info("Audit event logged")

	return nil
}

func (s *service) QueryEvents(ctx context.Context, filters map[string]interface{}, from, size int) ([]AuditEvent, error) {
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": buildQueryFilters(filters),
			},
		},
		"sort": []map[string]interface{}{
			{
				"timestamp": map[string]interface{}{
					"order": "desc",
				},
			},
		},
		"from": from,
		"size": size,
	}

	queryJSON, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}

	index := "hipaa_audit_*"
	res, err := s.es.Search(
		s.es.Search.WithContext(ctx),
		s.es.Search.WithIndex(index),
		s.es.Search.WithBody(strings.NewReader(string(queryJSON))),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var result struct {
		Hits struct {
			Hits []struct {
				Source AuditEvent `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	events := make([]AuditEvent, len(result.Hits.Hits))
	for i, hit := range result.Hits.Hits {
		events[i] = hit.Source
	}

	return events, nil
}

func buildQueryFilters(filters map[string]interface{}) []map[string]interface{} {
	var must []map[string]interface{}

	for field, value := range filters {
		must = append(must, map[string]interface{}{
			"match": map[string]interface{}{
				field: value,
			},
		})
	}

	return must
}
